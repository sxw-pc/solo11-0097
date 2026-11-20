# 对外证据包示例（合成数据）

本目录由 `coldhandoff.privacy_export` 基于冻结的 `batch-1` 与
`fixtures/export-contract.json` 生成，全部为虚构数据。同一批证据在两条
事先授权的交付契约下产生两份**实际字节不同**的包：

```
packages/evidence-export-2030-06-08/
├── regulator_full-regulator-primary/v1/      # 受权审计方：逐字节保真
└── partner_pseudonymous-partner-primary/v1/  # 合作承运方：脱敏重建
```

## 每个包的内容

| 文件 | 含义 |
| --- | --- |
| `manifest.json` | 包清单：合同、版本、密钥 id、计数、内容摘要与逐文件 SHA256 |
| `sources.json` / `sources/*` | 来源清单与来源字节（监管包为原文，合作包为重建受限视图） |
| `events.json` | 事件（合作包 payload 已递归脱敏并带导出哈希） |
| `issues.json` | 问题代码与（脱敏后的）详情 |
| `evidence.json` | source→event→evidence→decision 引用链，全部指向导出 id |
| `decisions.json` | 箱号判定与判定链 |
| `runs.json` | 规则运行（合作包只有收件方绑定的摘要承诺，无真实来源摘要） |
| `report.md` | Markdown 证据报告 |
| `receipt.json` | 收件确认（不含任何私有映射） |
| `verify/verification.json` | 发布前验证报告 |

## 两份包的关键差异

- 监管包 `sources/privacy-events.jsonl` 保留原始字节、原文件 SHA 与
  `MIRA-PRIVATE` 原文，可与数据库 BLOB 逐字节核对。
- 合作包来源文件被重命名为 `source-<导出id>.jsonl`，行首加入收件方绑定
  标记，嵌套 `payload`、Base64 原文、附件与异常详情统一替换为稳定伪名
  `PN-XXXXXXXXXXXX`，并给出**重算的导出来源 SHA**；原文件 SHA、原路径、
  原 BLOB 与私有映射均不在包内。
- 合作方仍可沿 `sources → events → evidence → decisions` 追到箱 A 的判定。

## 独立校验

无需数据库即可校验清单哈希与引用图闭合：

```
python -m coldhandoff export-verify \
  examples/privacy-export/packages/evidence-export-2030-06-08/partner_pseudonymous-partner-primary/v1
```

带数据库校验时，合作包会额外执行递归泄露扫描（JSON 文本、Markdown 与
Base64 解码字节），监管包会额外核对逐字节保真。原始 id/hash ↔ 导出
id/hash 的映射与伪名密钥只保存在本地 SQLite 台账，从不进入任何外包。
