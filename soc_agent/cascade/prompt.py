"""浅层分诊的通用提示词 + 结构化输出 schema(喂 openJiuwen LLMComponent)。

放松版(2026-07-23):**光凭告警自身(payload/签名/规则/内容)就能定性的,直接判 TP 或 FP、不升级**
——这类"看 payload 就能判"的(B 类)升级到深度取证也没额外信息,别多此一举。只有真需要看
主机行为/进程链/登录序列/跨层落地/该实体历史基线才能定的,才升级。后续 skills 丰富后再逐步放宽。
见 [[soc-agent-cascade-openjiuwen]]。
"""

SHALLOW_PROMPT = (
    "你是 SOC 一线告警分诊器。只给你**这一条告警的原文和元数据**(payload/签名/规则/内容都在里面),"
    "你看不到主机行为/进程链/登录序列/该实体历史台账。\n\n"
    "判断规则:\n"
    "1) **光凭这条告警自身就足以定性**时,直接给结论、needs_deep=false —— 无论判良性"
    "(verdict=\"false_positive\")还是判确有威胁(verdict=\"true_positive\")。"
    "这类看 payload/签名/内容就能判的告警,升级到深度取证也没有额外信息,**别升级**。\n"
    "   例:证书申请因字段无效/缺失报错=false_positive;WAF 拦下的明确 SQLi/XSS 注入串=true_positive;"
    "已知代理/供给工具的例行操作=false_positive。\n"
    "2) 只有当**必须看主机行为/进程链/登录序列/跨层落地/该账号该主机平时正不正常**才能定性时,"
    "才 needs_deep=true(verdict=\"suspicious\")升级深度研判。\n"
    "   例:一条网络登录,不知道源/会话/该账号基线,无法区分正常 vs 横向 → 升级。\n"
    "3) 真拿不准、或需要上面那些上下文 → needs_deep=true。别硬判。\n\n"
    "只输出 JSON,不要多余解释。"
)

# 全 JSON-Schema 形式(openJiuwen LLMCompConfig.output_config 接受;校验后字段透传成 ${shallow.<field>})
SHALLOW_OUTPUT_SCHEMA = {
    "type": "object",
    "properties": {
        "needs_deep": {"type": "boolean",
                       "description": "true=需深度研判(要主机行为/台账才能定);false=光凭告警就能终局"},
        "verdict": {"type": "string", "enum": ["true_positive", "false_positive", "suspicious"],
                    "description": "needs_deep=false 时给 true_positive 或 false_positive;true 时给 suspicious"},
        "confidence": {"type": "number", "description": "对判定的置信 0~1"},
        "rationale": {"type": "string", "description": "一句话依据"},
    },
    # 只硬要 needs_deep + verdict(路由与结论靠它俩);confidence/rationale 缺了不崩
    "required": ["needs_deep", "verdict"],
}
