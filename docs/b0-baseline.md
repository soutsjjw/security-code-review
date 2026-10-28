# B0 效能與品質基準

B0 應記錄來源 commit、規則版本、執行器、Run 與量測出處。不可把未提供的 Token、Agent 耗時視為零。

目前僅有未完成的歷史 Run，尚不足以作為新舊版本效能比較基線。

相同資料集上的獨立實跑，至少各三次，記錄中位數與範圍；已知弱點真值需在實跑前凍結。檔案與規則 completed 計數不得替代正式驗證。

## B0 工具用法

```bash
python scripts/b0_baseline.py --latest /path/to/logs/latest.json --output /tmp/b0.json
python scripts/b0_baseline.py --aggregate /tmp/b0-a.json /tmp/b0-b.json /tmp/b0-c.json --output /tmp/b0-summary.json
```

只有已完成且附可信來源版本識別的 Run 可作比較樣本。B0 的統計不代表完整審查已完成，也不會產生安全判定。
