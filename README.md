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

## 跨来源追加式防篡改证明

`audit_anchor` 在单文件哈希之上，把所有来源提交到一棵仅追加 Merkle 树（RFC 6962 树形，域隔离标签见合同 `anchor-contract.json`）：叶子绑定不可复用的 source id、原字节 SHA-256 与导入版本，按导入顺序追加；新来源只能加到末尾，旧来源的修正以撤销/替代叶追加，旧叶永不改写。单个当前根不足以证明历史——删掉首份来源重算的新根仍自洽，但无法通过旧根到新根的仅追加一致性验证。

- 包含证明：任意来源在当前树中的路径，验证者只需叶内容、树大小与根。
- 一致性证明：旧 n 叶检查点到新 m 叶检查点，验证者只持两根、两个树大小与证明即可确认旧前缀未被替换。
- 检查点策略：`local_signed` 立即本地签发；`dual_witness` 需合同两名见证在同一树大小、同一根、同一来源快照上签收。见证看到不同根时，双见证包保持待核实并记录分叉；已签发的本地包仍用其原根验证，不被静默重写。
- 叶分配、检查点与待签请求在同一个 `BEGIN IMMEDIATE` 事务提交，并发导入不会争同一叶位置；见证回执可重复、延迟或丢失，重试绑定完全相同的根/树大小，不同根的同编号签名被拒绝并记为分叉。崩溃后 `anchor-recover` 继续旧检查点或另起下一检查点，绝不产生两个互斥的同编号历史。测试中的见证是本地模拟（HMAC 签名）。

命令：`anchor-register` 冻结合同并锚定现有来源；`anchor-checkpoint --policy …` 提交检查点；`anchor-witness`（模拟见证签收）→ `anchor-ack` 登记回执；`anchor-inclusion` / `anchor-consistency` 出证明；`anchor-export` 导出 JSON+Markdown 证明包（含树根、包含/一致性证明、逐见证回执、分叉/恢复记录与验证命令）；`anchor-verify-package` / `anchor-verify-inclusion` / `anchor-verify-consistency` 供独立审计方离线验证。
