# Kerberoasting 响应策略(T1558.003)

> 这份文档喂给独立的 composer 环节:研判坐实(true_positive)后,据此从**处置接口文档**里挑选+排序基础处置原语、
> 把参数绑到实体角色,组装成响应计划(人审后才真做)。只写"该怎么处置该类攻击",不写研判逻辑(研判在 SKILL.md)。

## 本类攻击涉及的实体角色(可绑定)

- **requester** —— 发起取票的主体账号(正在 roasting 的那个普通用户账号)。**这是要遏制的攻击主体。**
- **target_service** —— 被取票的服务账号(带 SPN)。它的 NTLM 哈希已被随 TGS 票据带走、可离线爆破,
  **无论是否已破解,都应视其凭据已泄露**,需轮换。

## 响应目标与优先级

1. **止血:遏制 requester** —— 停止其继续扫票/用已破解凭据横向。
   - 首选 `disable_account(sam=requester)`(直接拒绝登录);
   - 若担心误伤正常业务账号、要更温和,可用 `add_to_group(sam=requester, group="Quarantine")`(移入受限组)替代。
2. **凭据补救:轮换 target_service 的口令** —— 哈希已被带走,必须让离线爆破出的口令作废。
   - 用 `expire_password(sam=target_service)`(强制下次登录改密,较温和);
   - 服务账号改密会中断依赖它的服务 —— 所以此步**必然 gated、需分析师协调改密窗口**,别自动。
3. **取证(若有来源主机可绑)**:破坏性动作前先 `collect_artifact` 保留现场。
   —— 当前判别只绑了账号角色;若上游提供了 requester 的来源主机角色,则把 collect_artifact 排到最前。

**建议顺序**:(可选 collect_artifact)→ 遏制 requester → 轮换 target_service 口令。

## 红线(绝不做)

- **绝不禁用/改密受保护账号**:krbtgt、Domain/Enterprise Admins、DC 机器账号 —— 护栏会硬拦,composer 也不该规划。
- **不要"禁用" target_service 账号**:直接禁用服务账号会立刻打断业务;对它只做**口令轮换**,不做 disable。
- **requester 是机器账号($ 结尾)不该走到这里** —— 那是跨域引荐票的豁免(FP),见 SKILL.md;真到这步说明判别已认定是普通用户 roasting。
- 破坏性步骤一律 gated(人审后才真做);只读取证可自动。

## 升级而非遏制的情形

- 证据显示对**高价值/蜜罐 SPN**、但低量无扇出、请求者无基线 → 研判本就应是 suspicious,不组遏制计划,交人工。
- 若已确证爆破成功(被 roast 账号从新主机登录),遏制之外还应扩大到该主机 —— 但主机隔离需有主机角色可绑,当前判别未提供时在计划里以 escalate 标注、交人工跟进。
