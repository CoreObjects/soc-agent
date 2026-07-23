"""浅层分诊的通用提示词 + 结构化输出 schema(喂 openJiuwen LLMComponent)。

保守:浅层只凭告警自身判**明显良性→终局 FP**;拿不准/像攻击/需要行为取证 → needs_deep=true 升级。
★浅层不下 true_positive(保召回:真攻击交深度层坐实+处置)。见计划 humming-twirling-moore。
"""

SHALLOW_PROMPT = (
    "你是 SOC 一线告警分诊器(浅层快判)。只给你**这一条告警的原文和元数据**,"
    "你看不到任何图谱/主机/进程链/登录序列取证。\n"
    "唯一任务:判断这条告警**能不能只凭它自身就明确定为误报(良性)**。\n\n"
    "规则(务必保守,宁可升级也绝不放过真攻击):\n"
    "1) 只有当告警本身足够明确、显然是良性/正常业务(已知扫描器、运维例行、自检、"
    "明显无害的请求等)时,才 needs_deep=false 且 verdict=\"false_positive\"。\n"
    "2) 出现下列任一,一律 needs_deep=true(升级深度研判):\n"
    "   - 像真实攻击/入侵,或需要看主机行为/进程链/登录序列才能坐实;\n"
    "   - 你对'是否良性'没有很高把握;\n"
    "   - 信息不足以定性。\n"
    "3) 你**不下 true_positive**;拿不准就升级——真正的攻击由深度研判去坐实和处置。\n\n"
    "只输出 JSON,不要多余解释。"
)

# 全 JSON-Schema 形式(openJiuwen LLMCompConfig.output_config 接受;会校验并把字段透传成 ${shallow.<field>})
SHALLOW_OUTPUT_SCHEMA = {
    "type": "object",
    "properties": {
        "needs_deep": {"type": "boolean",
                       "description": "true=升级深度研判;false=浅层终局判良性"},
        "verdict": {"type": "string",
                    "description": "needs_deep=false 时为 \"false_positive\";否则 \"suspicious\""},
        "confidence": {"type": "number", "description": "对判定的置信 0~1"},
        "rationale": {"type": "string", "description": "一句话依据"},
    },
    # 只硬要 needs_deep(路由靠它);其余给了更好、缺了不崩(小模型偶尔省字段,别让 schema 校验挂掉)
    "required": ["needs_deep"],
}
