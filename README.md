# 冷链交接采录台

离线导入交接扫描与温度日志，保留输入哈希、事件、问题和逐箱判定。所有样本是合成数据。

## 启动与测试

在仓库目录运行 `python -m coldhandoff demo`，打印报告路径；`python -m coldhandoff --help` 查看子命令；`python -m pytest -q` 运行测试。仅依赖 Python 3.11+ 标准库，测试需要 pytest。

## 数据流

来源文件 → 原始事件 → 设备序列与校时检查 → 箱号状态与封签检查 → 温度区间计算 → 决策 → JSON 证据报告。`batch` 一对多 `box`，`source_file` 一对多 `raw_event`；事件和问题指向来源，决策指向箱。事件不可覆盖，来源哈希用于幂等。缺口、未知箱号或冲突保留为问题，不能视作正常。

## 状态与规则

交接顺序为 dispatch → arrival → sign；open 与 reseal 必须配对。温度样本间隔不超过 30 分钟，必须覆盖运输区间；连续超阈值达到批次定义的分钟数判异常。结果为完整、异常、证据不足。规则版本保存在决策行。未实现人工复核写回。

## 温度时间校正

设备原始 `event_time` 不可变；评估时按同一设备相邻校时锚点生成可追溯的 `corrected_time` 与不确定范围（`time_correction` 表，含锚点引用与算式），再用校正后的时间重建交接区间、封签顺序、重叠读数取舍与温度暴露。批次配置 `correction` 选择规则：`step`（阶梯）对每个事件应用最近前置锚点偏移，适合校时器分段更新；`linear`（线性）在相邻锚点间插值偏移，适合时钟持续漂移。锚点缺失、锚点逆序、漂移超过批次 `max_clock_drift_s` 或覆盖不了交接边界时，事件记为 `raw_fallback` 并产生问题（`clock_uncorrectable`/`clock_anchor_disorder`/`clock_drift`/`clock_untrusted`），绝不悄悄退回原始时间；此类箱不能判完整。报告同时给出原始时间、修正时间、锚点证据与区间算式。

安装检查：在仓库目录运行 `python -m pip install . --no-build-isolation`；本地开发也可直接运行模块命令。报告同时生成 JSON 和 Markdown，`inspect` 子命令可追踪单个对象。

审计台账：Run 由规则版本和来源摘要确定，Evidence 关联原始对象与来源，Decision 引用 Run；重复核验保持同一输入的报告稳定。

原始来源字节保存在 SQLite BLOB 中，JSON 证据包以 Base64 表示字节；修改输入文件不会覆盖已采录证据。
