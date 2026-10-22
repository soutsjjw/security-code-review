using System.Text.Json;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;

if (args.Length != 2)
{
    Console.Error.WriteLine("Usage: roslyn-indexer <source-root> <manifest-json>");
    return 2;
}

var root = Path.GetFullPath(args[0]);
var prefix = Path.TrimEndingDirectorySeparator(root) + Path.DirectorySeparatorChar;
var manifest = JsonSerializer.Deserialize<string[]>(File.ReadAllText(args[1])) ?? [];
var files = new List<object>();
var errors = new List<string>();
foreach (var relative in manifest.Order(StringComparer.Ordinal))
{
    try
    {
        var absolute = Path.GetFullPath(Path.Combine(root, relative));
        if (!absolute.StartsWith(prefix, StringComparison.OrdinalIgnoreCase) ||
            Path.GetExtension(absolute) != ".cs" || !File.Exists(absolute))
            throw new InvalidOperationException("Invalid or missing source path");
        var source = File.ReadAllText(absolute);
        var syntax = CSharpSyntaxTree.ParseText(source, path: absolute);
        var rootNode = syntax.GetRoot();
        int Line(Microsoft.CodeAnalysis.SyntaxNode node) =>
            syntax.GetLineSpan(node.Span).StartLinePosition.Line + 1;
        var types = rootNode.DescendantNodes().OfType<BaseTypeDeclarationSyntax>()
            .Select(x => new { name = x.Identifier.ValueText, line = Line(x) }).ToArray();
        var methods = rootNode.DescendantNodes().OfType<BaseMethodDeclarationSyntax>()
            .Select(x => new { name = x switch
                {
                    MethodDeclarationSyntax m => m.Identifier.ValueText,
                    ConstructorDeclarationSyntax c => c.Identifier.ValueText,
                    _ => x.GetType().Name
                }, line = Line(x) }).ToArray();
        var calls = rootNode.DescendantNodes().OfType<InvocationExpressionSyntax>()
            .Select(x => new { name = x.Expression.ToString(), line = Line(x) }).ToArray();
        files.Add(new { path = relative.Replace('\\', '/'), types, methods, calls,
                        parse_errors = syntax.GetDiagnostics().Count(x => x.Severity ==
                            Microsoft.CodeAnalysis.DiagnosticSeverity.Error) });
    }
    catch (Exception ex)
    {
        errors.Add(relative + ": " + ex.GetType().Name);
    }
}
Console.WriteLine("SCROSLYN_JSON:" + JsonSerializer.Serialize(new { files, errors }));
return errors.Count == 0 ? 0 : 1;
