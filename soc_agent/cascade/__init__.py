"""浅度研判(cascade 第二档)——"浅判→判不动才升级深度"。

浅层 LLM 用 QwenClient(直连昇腾 qwen);曾用 openJiuwen,因其 LLM 客户端持续负载 ~50% 崩已换掉,
见 docs/openjiuwen-踩坑总结.md。只新增、不动深度层(现有 skills / run_pipeline)与经验层。
"""
