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

## 可复用保温周转箱的回收再投放

`coldhandoff/planner.py` 与 `coldhandoff/assets.py` 在不读取温度 `decision`、不改动车辆装载题面的前提下，交付独立的周转资产库存与下轮领用计划。资产数据全部落在版本化的 `asset_*` 表中。

作业状态机按真实顺序推进：`returned → washed → recharging → recharged → ready → reserved → dispatched`。待检隔离（`quarantine`）未放行或污染（`contaminated`）未通过的容器不能跳过洗消；洗消台容量为 1、同一时刻只能处理一只，蓄冷柜按容量展开为槽位、每只容器占槽直到蓄冷完成；采购的新容器按合同到货时刻才进入可用库存。

排程是全局精确求解而非“第一只可见容器分给第一张需求”：阶段一枚举有限洗消台上的全部可行洗消排程并做组件支配剪枝，阶段二对每个洗消排程用容量化蓄冷槽位求最早可行蓄冷，再用记忆化 DFS 把就绪容器与采购箱指派给需求。离线精确规模限制为 10 只归还容器、8 个需求、3 个洗消台/蓄冷柜。

调用方在出计划前选择合同允许的策略：

- `reuse_first`：先最小化外部采购数量，再最小化含迟到罚金的总费用；
- `deadline_first`：先最大化截止前完成领用的需求数，再最小化总费用。

完全并列时按容器/需求 ID 稳定裁定，同一合同的计划摘要可复现。迟到允许但显式标出迟到分钟、按 30 分钟向上取整的罚金以及实际派给的新箱。

### 版本化、事务与恢复

合同或源盒更正会生成新的案例版本（`asset_case.version`、`supersedes_version`），旧版本库存与 `asset_state_history`/`asset_operation` 审计保留；已确认的领用不可覆写，只能以新版本重新规划。`asset-confirm` 在单个事务内绑定资产版本、设备时段与需求身份，并校验需求排他、设备时段不重叠、一只容器最多一个需求；重复确认幂等，不会重复领用或采购。中断后用 `asset-recover` 释放未确认草案的槽位锁、把卡在中间态的容器回滚到上一持久态，避免一只容器同时“在柜内”与“已发出”。

### 资产 CLI

```
python -m coldhandoff asset-register <contract.json> --db cold.db
python -m coldhandoff asset-plan --db cold.db --case <case_id> --policy reuse_first|deadline_first
python -m coldhandoff asset-confirm --db cold.db --plan <plan_id>
python -m coldhandoff asset-recover --db cold.db --case <case_id>
python -m coldhandoff asset-status --db cold.db --case <case_id>
python -m coldhandoff asset-report --db cold.db --plan <plan_id> --out allocation.json
```

`asset-report` 同时生成 JSON 与 Markdown 领用报告，包含各容器作业/保管时间线、各需求领用来源、剩余/占用库存、准时/逾期、洗消/采购/迟到费用以及指向合同条目和采购合同的来源证据。`fixtures/asset-cycle.json` 的精确解见 `tests/test_asset_cycle.py`。
