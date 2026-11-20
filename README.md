# 冷链交接采录台

离线导入交接扫描与温度日志，保留输入哈希、事件、问题和逐箱判定。所有样本是合成数据。

## 启动与测试

在仓库目录运行 `python -m coldhandoff demo`，打印报告路径；`python -m coldhandoff --help` 查看子命令；`python -m pytest -q` 运行测试。仅依赖 Python 3.11+ 标准库，测试需要 pytest。

## 数据流

来源文件 → 原始事件 → 设备序列与校时检查 → 箱号状态与封签检查 → 温度区间计算 → 决策 → JSON 证据报告。`batch` 一对多 `box`，`source_file` 一对多 `raw_event`；事件和问题指向来源，决策指向箱。事件不可覆盖，来源哈希用于幂等。缺口、未知箱号或冲突保留为问题，不能视作正常。

## 状态与规则

交接顺序为 dispatch → arrival → sign；open 与 reseal 必须配对。温度样本间隔不超过 30 分钟，必须覆盖运输区间；连续超阈值达到批次定义的分钟数判异常。结果为完整、异常、证据不足。规则版本保存在决策行。当前时间校准只检查锚点偏移漂移，尚未据此重算事件时间；未实现人工复核写回。

安装检查：在仓库目录运行 `python -m pip install . --no-build-isolation`；本地开发也可直接运行模块命令。报告同时生成 JSON 和 Markdown，`inspect` 子命令可追踪单个对象。

审计台账：Run 由规则版本和来源摘要确定，Evidence 关联原始对象与来源，Decision 引用 Run；重复核验保持同一输入的报告稳定。

原始来源字节保存在 SQLite BLOB 中，JSON 证据包以 Base64 表示字节；修改输入文件不会覆盖已采录证据。

## 对外分级证据包

`privacy_export` 按事先授权的收件合同发布不可覆写的证据包版本，支持两类合同：

- `regulator_full`（受权审计方）：原始来源字节、事件、issue/evidence/decision 与原 SHA 全部保留，可逐字节核对。
- `partner_pseudonymous`（合作承运方）：从原始字节**重建**受限视图，保留箱关系、事件顺序、问题代码与判定链；采录人、原始来源路径、原始 BLOB 及可反推私有身份的字段被递归变换（嵌套 `payload`、Base64 原文、Markdown/JSON 附件、异常详情与引用键一致处理）。改过的对象只携带重算的导出哈希，不谎称等于原来源 SHA。

伪名按“收件方 + 伪名密钥”派生：同一身份在同一合作方包内稳定，跨合作方与跨密钥轮换不可关联。原始 id/hash ↔ 导出 id/hash 映射和伪名密钥只保存在本地数据库，从不进入外包；合作包清单只给收件方绑定的摘要承诺，不含真实来源摘要。

发布流程为暂存→泄露扫描→原子确认，中断可用 `export-resume` 恢复，含私有原文的暂存包永远无法进入合作方收件目录。批次来源新增、证据补录、合同更改或密钥轮换后只能发布新版本，旧包与私有映射不可覆写；并发导出绑定同一冻结来源摘要，来源漂移会被拒绝。

命令：

```
python -m coldhandoff contract-register --db <db> --contract <contract.json>
python -m coldhandoff key-rotate --db <db> [--key-id <id>]
python -m coldhandoff export-stage --db <db> --case <case> --contract-kind regulator_full|partner_pseudonymous --out-root <dir> [--recipient <id>] [--key-id <id>]
python -m coldhandoff export-confirm --db <db> --package-id <id> --out-root <dir>
python -m coldhandoff export-resume --db <db> --case <case> --contract-kind <kind> --recipient <id> --out-root <dir>
python -m coldhandoff export-verify <package-dir> [--db <db>]
```

示例产物见 `examples/privacy-export/`（仅合成数据）。
