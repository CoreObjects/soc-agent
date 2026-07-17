"""行为指纹:格式无关的规范发现集(第二类经验:模糊召回)。

构造(层层归一,对无关差异钝感、对决定性差异敏感):
- 取选定 finding_id 子集,每类留其 canon(决定性 attrs)。
- 实例值(账号/主机/IP/域,由 bindings 给出)→ ``<role>`` 占位符,免疫环境差异。
- 易变字段(时间戳/PID/GUID/端口/session)禁入;复杂值(list/dict)不进 canon。
- 进程名/模块名/enc/桶/布尔等 **语义值保留**(如 src_image 原始值 = 可移植承重 key,守红线)。

匹配:同 skill 分区内,规范 ID 重合 + 决定性 attr 一致(占位符=通配)→ 加权重合度打分(阈值命中,非全等)。
误报指纹阈值放宽(量大从宽);威胁指纹严一些。见 [[soc-signature-portability-redline]]。
"""

__all__ = ["build_fingerprint", "match"]

_VOLATILE = ("time", "timestamp", "_at", "pid", "guid", "session", "port", "nonce")


def _is_volatile(name) -> bool:
    n = str(name).lower()
    return any(k in n for k in _VOLATILE)


def _is_abstract_role(role) -> bool:
    """实例身份角色(账号/主机/IP/域/SID/用户)→ 抽象;进程/镜像/GUID → 保留(语义 key)。"""
    r = str(role).lower()
    if "process" in r or "image" in r or "guid" in r:
        return False
    return any(k in r for k in ("account", "host", "ip", "domain", "user", "sid"))


def _placeholder_map(bindings, abstract_roles) -> dict:
    m = {}
    for role, val in (bindings or {}).items():
        if val is None:
            continue
        use = (role in abstract_roles) if abstract_roles is not None else _is_abstract_role(role)
        if use:
            m[str(val)] = f"<{role}>"
    return m


def _canon_attrs(attrs, pmap) -> dict:
    out = {}
    for k, v in (attrs or {}).items():
        if _is_volatile(k):
            continue
        if isinstance(v, (list, dict)):
            continue                      # 复杂值不入 canon(仅标量决定性字段)
        out[k] = pmap.get(str(v), v)      # 实例值 → 占位符;其余保留
    return out


def _by_id(findings) -> dict:
    idx = {}
    for f in findings or []:
        if hasattr(f, "finding_id"):
            fid, attrs = f.finding_id, (f.attrs or {})
        else:
            fid, attrs = f.get("finding_id"), (f.get("attrs") or {})
        if fid is None:
            continue
        idx.setdefault(fid, []).append(attrs)
    return idx


def build_fingerprint(findings, bindings=None, subset_ids=None, abstract_roles=None, weights=None) -> dict:
    """从 findings + bindings 构造实例无关指纹。subset_ids=None 用全部;weights 可给决定性发现更高权重。"""
    idx = _by_id(findings)
    ids = sorted((set(subset_ids) & set(idx)) if subset_ids is not None else set(idx))
    pmap = _placeholder_map(bindings, abstract_roles)
    canon = {fid: _canon_attrs(idx[fid][0], pmap) for fid in ids}
    w = {fid: float((weights or {}).get(fid, 1.0)) for fid in ids}
    return {"finding_ids": ids, "canon": canon, "weights": w}


def _attr_ok(canon_v, k, cur_attrs) -> bool:
    if isinstance(canon_v, str) and canon_v.startswith("<") and canon_v.endswith(">"):
        return k in cur_attrs             # 占位符 = 通配(该 attr 存在即可)
    return cur_attrs.get(k) == canon_v


def _fid_matches(canon_attrs, cur_list) -> bool:
    if not cur_list:
        return False
    if not canon_attrs:
        return True
    return any(all(_attr_ok(cv, k, ca) for k, cv in canon_attrs.items()) for ca in cur_list)


def match(fp, findings, threshold=1.0):
    """指纹 vs 当前 findings。返回 (hit, score, matched_ids)。score = 命中权重 / 总权重。"""
    idx = _by_id(findings)
    ids = fp.get("finding_ids") or []
    canon = fp.get("canon") or {}
    weights = fp.get("weights") or {}
    total = sum(float(weights.get(fid, 1.0)) for fid in ids) or 1.0
    matched = [fid for fid in ids if _fid_matches(canon.get(fid) or {}, idx.get(fid))]
    score = sum(float(weights.get(fid, 1.0)) for fid in matched) / total
    return (score >= threshold and bool(matched)), score, matched
