using System.Text.Json;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;

if (args.Length != 2)
{
    Console.Error.WriteLine("Usage: roslyn-indexer <source-root> <manifest-json>");
    return 2;
}

var sourceRoot = Path.GetFullPath(args[0]);
var prefix = Path.TrimEndingDirectorySeparator(sourceRoot) + Path.DirectorySeparatorChar;
var manifest = JsonSerializer.Deserialize<string[]>(File.ReadAllText(args[1])) ?? [];
var trees = new SortedDictionary<string, SyntaxTree>(StringComparer.Ordinal);
var errors = new List<string>();
var pathComparer = OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal;
foreach (var relative in manifest.Distinct(StringComparer.Ordinal).Order(StringComparer.Ordinal))
{
    try
    {
        var absolute = Path.GetFullPath(Path.Combine(sourceRoot, relative));
        if (!absolute.StartsWith(prefix, pathComparer) ||
            !Path.GetExtension(absolute).Equals(".cs", StringComparison.OrdinalIgnoreCase) ||
            !File.Exists(absolute))
            throw new InvalidOperationException("Invalid or missing source path");
        trees.Add(relative.Replace('\\', '/'),
                  CSharpSyntaxTree.ParseText(File.ReadAllText(absolute), path: absolute));
    }
    catch (Exception ex)
    {
        errors.Add(relative + ": " + ex.GetType().Name);
    }
}

// This compilation provides *candidate* symbol binding, not a faithful MSBuild build.
// Project references, generators, conditional compilation and external assemblies can differ.
// In particular, an interface/virtual dispatch target is never a verified runtime target.
var runtimeAssemblies = ((string?)AppContext.GetData("TRUSTED_PLATFORM_ASSEMBLIES"))?
    .Split(Path.PathSeparator, StringSplitOptions.RemoveEmptyEntries) ?? [];
var references = runtimeAssemblies.Distinct(StringComparer.OrdinalIgnoreCase)
    .Where(File.Exists).Select(x => MetadataReference.CreateFromFile(x)).ToArray();
var compilation = CSharpCompilation.Create(
    "SecurityReviewStructuralCandidates", trees.Values, references,
    new CSharpCompilationOptions(OutputKind.DynamicallyLinkedLibrary));
var allTypes = trees.Values.SelectMany(tree => tree.GetRoot().DescendantNodes()
        .OfType<BaseTypeDeclarationSyntax>())
    .Select(node => compilation.GetSemanticModel(node.SyntaxTree).GetDeclaredSymbol(node))
    .OfType<INamedTypeSymbol>().ToArray();

string? PathInManifest(SyntaxReference reference)
{
    var absolute = Path.GetFullPath(reference.SyntaxTree.FilePath);
    if (!absolute.StartsWith(prefix, pathComparer)) return null;
    var relative = Path.GetRelativePath(sourceRoot, absolute).Replace('\\', '/');
    return trees.ContainsKey(relative) ? relative : null;
}

object[] Declarations(IMethodSymbol symbol)
{
    return symbol.DeclaringSyntaxReferences
        .Select(reference => (reference, path: PathInManifest(reference)))
        .Where(item => item.path is not null)
        .Select(item => (object)new
        {
            path = item.path, method = symbol.Name,
            line = item.reference.SyntaxTree.GetLineSpan(item.reference.Span).StartLinePosition.Line + 1,
            containing_type = symbol.ContainingType?.ToDisplayString()
        })
        .ToArray();
}

var files = new List<object>();
foreach (var (relative, syntax) in trees)
{
    try
    {
        var syntaxRoot = syntax.GetRoot();
        var model = compilation.GetSemanticModel(syntax);
        int Line(SyntaxNode node) => syntax.GetLineSpan(node.Span).StartLinePosition.Line + 1;
        string? ContainingType(SyntaxNode node) =>
            node.Ancestors().OfType<BaseTypeDeclarationSyntax>().FirstOrDefault()?.Identifier.ValueText;
        string? ContainingMethod(SyntaxNode node) =>
            node.Ancestors().OfType<BaseMethodDeclarationSyntax>().FirstOrDefault() switch
            {
                MethodDeclarationSyntax m => m.Identifier.ValueText,
                ConstructorDeclarationSyntax c => c.Identifier.ValueText,
                _ => null
            };
        var types = syntaxRoot.DescendantNodes().OfType<BaseTypeDeclarationSyntax>()
            .Select(node => new
            {
                name = node.Identifier.ValueText,
                line = Line(node),
                full_name = model.GetDeclaredSymbol(node)?.ToDisplayString(),
                bases = node.BaseList?.Types.Select(x => x.Type.ToString()).ToArray() ?? []
            }).ToArray();
        var methods = syntaxRoot.DescendantNodes().OfType<BaseMethodDeclarationSyntax>()
            .Select(node => new
            {
                name = node switch
                {
                    MethodDeclarationSyntax m => m.Identifier.ValueText,
                    ConstructorDeclarationSyntax c => c.Identifier.ValueText,
                    _ => node.GetType().Name
                },
                line = Line(node),
                end_line = syntax.GetLineSpan(node.Span).EndLinePosition.Line + 1,
                containing_type = ContainingType(node),
                parameter_count = node.ParameterList.Parameters.Count,
                full_signature = model.GetDeclaredSymbol(node)?.ToDisplayString()
            }).ToArray();
        var calls = syntaxRoot.DescendantNodes().OfType<InvocationExpressionSyntax>()
            .Select(call =>
            {
                var info = model.GetSymbolInfo(call);
                var selected = info.Symbol as IMethodSymbol;
                var receiverNode = (call.Expression as MemberAccessExpressionSyntax)?.Expression;
                var receiverType = receiverNode is null ? null
                    : model.GetTypeInfo(receiverNode).Type?.ToDisplayString();
                var resolved = selected is not null && info.CandidateReason == CandidateReason.None;
                var dispatch = resolved && (selected!.ContainingType.TypeKind == TypeKind.Interface
                                             || selected.IsVirtual || selected.IsAbstract);
                var methodSymbols = new List<IMethodSymbol>();
                if (resolved) methodSymbols.Add(selected!);
                if (resolved && selected!.ContainingType.TypeKind == TypeKind.Interface)
                {
                    foreach (var type in allTypes.Where(x => x.TypeKind == TypeKind.Class))
                    {
                        var impl = type.FindImplementationForInterfaceMember(selected!) as IMethodSymbol;
                        if (impl is not null) methodSymbols.Add(impl);
                    }
                }
                else if (resolved && dispatch)
                {
                    // A virtual call may bind to an override at runtime; list known overrides
                    // as candidates even if the callsite binds to its base declaration.
                    foreach (var type in allTypes.Where(x => x.TypeKind == TypeKind.Class))
                    foreach (var member in type.GetMembers(selected!.Name).OfType<IMethodSymbol>())
                    {
                        for (var overridden = member.OverriddenMethod;
                             overridden is not null; overridden = overridden.OverriddenMethod)
                        {
                            if (SymbolEqualityComparer.Default.Equals(
                                    overridden.OriginalDefinition, selected!.OriginalDefinition))
                            {
                                methodSymbols.Add(member);
                                break;
                            }
                        }
                    }
                }
                var targets = methodSymbols
                    .SelectMany(Declarations)
                    .DistinctBy(x => JsonSerializer.Serialize(x))
                    .ToArray();
                return new
                {
                    name = call.Expression.ToString(),
                    called_method = call.Expression switch
                    {
                        MemberAccessExpressionSyntax member => member.Name.Identifier.ValueText,
                        IdentifierNameSyntax id => id.Identifier.ValueText,
                        _ => call.Expression.ToString()
                    },
                    receiver = receiverNode?.ToString(),
                    receiver_type = receiverType,
                    argument_count = call.ArgumentList.Arguments.Count,
                    containing_type = ContainingType(call),
                    containing_method = ContainingMethod(call),
                    line = Line(call),
                    semantic_state = !resolved ? "unresolved"
                        : dispatch ? "dispatch_candidate" : "symbol_candidate",
                    semantic_targets = targets,
                    candidate_symbol_count = info.CandidateSymbols.Length
                };
            }).ToArray();
        files.Add(new
        {
            path = relative, types, methods, calls,
            parse_errors = syntax.GetDiagnostics().Count(x => x.Severity == DiagnosticSeverity.Error)
        });
    }
    catch (Exception ex)
    {
        errors.Add(relative + ": " + ex.GetType().Name);
    }
}

Console.WriteLine("SCROSLYN_JSON:" + JsonSerializer.Serialize(new
{
    files, errors, binding_scope = "synthetic_workspace_compilation",
    warning = "Symbol/dispatch resolution yields candidates only; inspect actual project references and DI."
}));
return errors.Count == 0 ? 0 : 1;
