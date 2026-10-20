# 70 項資安基線的規範與發布政策（正式版）

## 定位與範圍
- 公司共用、技術中立，僅保留固定的 70 項檢核 ID；不得內嵌歷史專案掃描結論。
- 可支援 Web/API、行動應用、批次程式、背景服務，但不表示每項在所有系統都適用。
- OWASP ASVS 5.0.0 提供可驗證技術要求；OWASP Top 10:2025 是風險分類，不能當法規合規證明。
- 國資院《WEB 應用程式安全參考指引》V3.2 與附件 1、3 已建版本化對照；附件 2 尚未提供。來源對照不代表每個受測系統已實際驗證或符合法規。

## 規範優先序
1. 對本專案主體、使用情境已生效且適用的法律、命令、強制控制及正式核准豁免。
2. 合約、主管機關或標案正式規範及經核定的系統等級控制。
3. 公司正式發布的資安政策、資料分級、加密／紀錄保留／帳密／異常通知門檻。
4. OWASP ASVS 與 Code Review 指引等技術參考，依系統風險選擇適用範圍。

## 分級不得混淆
- 臺灣『資通安全責任等級 A～E』與『系統防護需求分級（普/中/高）』是不同概念。
- OWASP ASVS L1/L2/L3 為另一種驗證深度，不得自動將『中』對應為 ASVS L2。
- Project Profile 應分別保存這些資料，未知狀態為 unknown 或 not_classified，不得由 AI 推測。

## 先例與等效控制
- AU-02 密碼週期性更換、AU-05 CAPTCHA、AC-03/AC-06/PD-06 IP 白名單、PD-01 個資同意、PD-05 逐欄加密均非放諸所有系統皆準的唯一實作。
- 判定時先看已生效適用要求，再確認是否有可驗證的等效控制，不可僅根據缺少特定程式碼就 Fail。
- Web 應用程式資安掃描不等於滲透測試、部署合規驗證或個資法遵查核。

## 驗證邊界
- 原始碼證據：使用 Repository 相對路徑、行號、Commit SHA；不可複製真實秘密。
- 部署/平台證據：須有環境、責任人、取得日期、文件識別及權限界限。
- 未取證的控制應 Review，不能自動算 Pass；N/A 必須說明功能/法定義務不適用。
- 同一漏洞可對應多檢核 ID，但 finding 不重複計數；Fail 規則數不等於漏洞數。

## 版本與發布

- **核心規則集 v2.0.0 為正式版**，發布日期 2026-10-20，`release_status: stable`；公司資安簽核**不是本 Skill 規則集發版門檻**。
- 正式版代表版本及檔案結構已固定，**不等於法律／主管機關認證、單一機關的責任等級核定或個別受測系統合規**。
- 不得以核心規則 Pass 自動推定新標準對照、制度控制、動態測試或獨立防護基準符合；新要求需真實證據。
- 往後規則實質變更，需維護版本、規範登錄、影響評估、報告 Schema 與測試；公司內部政策或風險接受仍依各受測專案自身權責判斷。
- 既有 `2.0.0-rc1` `assessment.json` 保留向下相容，原 Findings、證據、進度不得抹除，並需補查版本發布後新增的規範對照。

## 權威參考來源
- [OWASP ASVS 5.0.0](https://github.com/OWASP/ASVS)
- [OWASP Top 10:2025](https://top10.owasp.org/2025/)
- [OWASP Secure Code Review Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Secure_Code_Review_Cheat_Sheet.html)
- [國家資通安全研究院共通規範](https://www.nics.nat.gov.tw/cybersecurity_resources/reference_guide/Common_Standards/)
- [資通安全責任等級分級辦法](https://law.moj.gov.tw/LawClass/LawAll.aspx?pcode=A0030304)
- [個人資料保護法](https://law.moj.gov.tw/LawClass/LawAll.aspx?PCode=I0050021)
