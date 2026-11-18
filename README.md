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

## 货箱实体标签制发

标签制发是独立于温度判定的物理流程：不读取 `decision`，仅依赖真实业务箱与冻结的收件合同。运行 `python -m coldhandoff label-demo --workdir <dir>` 可在本地用模拟设备走完整流程并生成审计报告；设备只写本地文件，不连接真实打印机或扫描器。

### 两种事先授权的版式（模板 TPL-1）

- `direct_recipient`：纸面打印可见客户名（A→`CLIENT-ALPHA`、B→`CLIENT-BETA`）加箱号与序列号，无需额外查询但暴露客户名。
- `opaque_pickup`：纸面只打印取件令牌（A→`TKN-A-001`、B→`TKN-B-002`）加箱号与序列号，收件方只能由授权扫描查私有映射得到；纸面不出现客户名。

一次作业（job）只能确认一种版式，另一种是未执行对照。两种版式渲染为**不同的确定字节与不同内容摘要**，并以最终出纸和验扫字节证明，而非只在 JSON 中改 `mode`。

### 生命周期与不变量

1. 打印前把箱 ID、收件方/令牌、序列号、模板版本渲染为确定字节并计算 SHA256；事务预留从未使用过的序列号（`serial_ledger`，序列号为主键）。
2. 打印命令带不可重复 nonce；PRN-1 在本地维护只追加、哈希链防篡改的命令日志与出纸日志，纸片以字节文件落盘。ACK 只证明命令送达。
3. SCAN-1 对贴在**正确业务箱**上的实物标签回读同一序列号与内容摘要后，状态才置为 `applied`；错箱、摘要不符、已作废/隔离序列号一律拒绝并记录。
4. 任何时刻一个序列号至多对应一张有效标签、每箱至多一张当前有效标签（部分唯一索引）；`label_event` 由触发器保证只追加，销毁证据不可覆写。
5. 设备日志位于 SQLite 之外，数据库回滚不会让纸质标签消失；恢复一律先查出纸/验扫日志。

### 卡纸恢复（PRN-1 在 SER-0001 出纸后、ACK 前中断）

`label-recover --disposition` 提供三个显式分支：`paper_recoverable`（纸片可核实且正确贴于 A，沿用原序列号验扫）、`paper_destroyed`（登记销毁证据后作废并以新号补印，替换链可追溯）、`whereabouts_unknown`（旧号进入隔离，不自动重试，杜绝两张有效 SER-0001）。错误更正走显式撤销（`label-revoke`）与补印（`label-reprint`）。

### 命令与报告

子命令包括 `label-register`、`label-produce`、`label-apply`、`label-reconcile`、`label-redeliver`、`label-recover`、`label-quarantine`、`label-revoke`、`label-reprint`、`label-revise`、`label-report` 等。`label-report` 生成 JSON 与 Markdown 审计报告，列出当前可用序列号、全部曾印或状态不确定的纸片、替换链、合同版本绑定与设备日志哈希链校验结果。收件合同改版后旧字节的绑定摘要失效，不能冒充新标签。

