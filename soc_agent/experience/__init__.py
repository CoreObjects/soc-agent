"""第二类经验层:取证结果 ↔ 研判结论 ↔ 处置剧本 的映射(qwen 蒸馏,落 openGauss + 进程内缓存)。

流水线三阶段"哪步有经验用哪步"里的【研判/处置】经验:
- 行为指纹(误报业务指纹 / 威胁指纹)+ 威胁判定规则(DSL)—— 见 fingerprint.py / dsl.py(后续 Phase)。
- 案例快照(cases)—— 回归考试语料(图台账不存 findings,故这里另存)。见 cases.py。

设计见 [[soc-agent-experience-v2-design]]。红线见 [[soc-signature-portability-redline]]。
"""
