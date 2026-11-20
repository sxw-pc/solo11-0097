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

`coldhandoff.audit_anchor` 在原始来源之上建立只追加的来源树，证明后续导入没有删除、改序或替换已公布的旧来源。Merkle 规则在 `coldhandoff/merkle.py`：

- 叶子绑定不可复用的 `source_id`、原字节 SHA-256 与导入版本，按 `source_file.id` 导入顺序排列；
- 域隔离编码：`SHA256(leaf_tag ‖ 0x00 ‖ 规范化 JSON)`，内部结点 `SHA256(node_tag ‖ 0x00 ‖ 左 ‖ 右)`，空树为 `SHA256(node_tag ‖ 0x00)`；
- 叶子序号持久化在 SQLite，`BEGIN IMMEDIATE` 事务保证并发导入不会争用同一叶位；
- 包含路径供任意源复查；一致性证明让只持有旧根、新根、两个树大小与证明的审计方确定旧前缀未被替换。删除首份来源后重算整棵树虽然自洽，却无法通过已交付旧根到新根的前缀一致性验证。
- 旧来源修正只能追加 `revoke`/`replace` 叶，旧叶永不修改。

检查点与见证：

- 叶集合、根、检查点与待签请求在同一事务提交；检查点编号与树大小不可重排；
- `local_signed` 在发布时立即签发当前根、大小与单源包含路径，交内部审计；
- `dual_witness` 需合同内两个见证在同一树大小、同一根与同一来源快照上签收；
- 见证 ACK 可重复、延迟或丢失：重试绑定完全相同的根/树大小/快照，不同签名或不同根不会覆盖既有回执，而会记为分叉；双见证包保持 `pending_verification` 并展示分叉，本地包仍按原根验证；
- 故障注入点：算完根未持久化、检查点提交后未送签、一个见证签收后崩溃、签名在后续来源之后到达。`recover` 可继续旧检查点或另起下一检查点，但绝不产生两个互斥的同编号历史。

命令（`--db` 指向已 `init`/`ingest` 的库，`--contract` 指向 `fixtures/anchor-contract.json`）：

```bash
python -m coldhandoff anchor-status   --db cold.db --contract anchor-contract.json
python -m coldhandoff anchor-append   --db cold.db --contract anchor-contract.json --from-ingest
python -m coldhandoff anchor-publish  --db cold.db --contract anchor-contract.json --policy local_signed
python -m coldhandoff anchor-witness-ack --db cold.db --contract anchor-contract.json --checkpoint 1 --witness W1
python -m coldhandoff anchor-bundle   --db cold.db --contract anchor-contract.json --checkpoint 1 \
    --consistency-from 0 --out out/bundle.json --keyring keys.json
python -m coldhandoff anchor-inclusion --db cold.db --contract anchor-contract.json \
    --source-id source-anchor-2030-06-09:source:000001 [--checkpoint 1]
python -m coldhandoff anchor-recover  --db cold.db --contract anchor-contract.json [--advance]
python -m coldhandoff anchor-verify   --bundle out/bundle.json [--keyring keys.json]
```

`anchor-bundle` 输出 JSON 与同名 Markdown，含树根、叶表、包含/一致性证明、逐见证回执、分叉/恢复记录和验证命令；`anchor-verify` 只需证据包（签名校验另需 `--keyring`，可用 `anchor-keyring` 从本地库导出）。`anchor-append` 也接受 `--source-id/--bytes-sha256`，`anchor-correction` 追加撤销/替代叶。所有见证均为本地模拟，不联网。
