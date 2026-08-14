"""端到端第 2 步的选靶器:把演练图里的告警列出来,并**说明每条值得验什么**。

★为什么单独一个脚本而不是在 shell 里塞 python 单行:
  这条路径要在真机上跑,而 heredoc 里的引号/转义在本仓已经坑过好几次
  (中文引号被规范化成 ASCII → SyntaxError,现象只剩一句 'NoneType' object is not callable)。

用法:  PYTHONPATH=. python scripts/e2e_alerts.py          # 列出来
       PYTHONPATH=. python scripts/e2e_alerts.py --uids   # 只吐 uid,给 shell 循环用
"""
import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

Q = """
MATCH (a:Alert)<-[:TRIGGERED]-(e:Event)
RETURN a.alert_uid   AS uid,
       a.source      AS source,
       a.detector_class AS cls,
       a.rule_id     AS rule,
       a.rule_description AS desc,
       a.severity    AS sev,
       a.severity_native  AS sev_native,
       a.severity_scale   AS sev_scale,
       e.activity    AS activity,
       e.source      AS ev_source,
       e.event_time  AS ev_time
ORDER BY coalesce(a.severity, -1) DESC, a.rule_id
"""

# 每条告警"值得验什么" —— 写在这里而不是口头说,免得跑完只剩一堆输出没人知道该看哪。
WHY = {
    "3021": "★主菜:锚在 10.20.30.5→203.0.113.77 的流上,而那条聚合边下面压着 120 次心跳。"
            "同时考验 endpoint pivot(WP7 建的:网络源没有进程主语)与跨源取证"
            "(同一个 C2 地址被科东/Zeek/CEF 三个源各连了一遍)。",
    "18433": "Web 利用(T1190)。锚点在 HTTP 事务上,取证要能顺到落地那一串"
             "(科东 536 的 java→sh→curl 与 534 写 shell.jsp)。",
    "Scan::Port_Scan": "★这条**没有严重度**(Zeek 不给刻度)。专门用来验研判侧"
                       "不会因为 severity 为空就把它漏掉 —— 三值逻辑下 `sev>=7` 恒不成立。",
    "00033": "URL 过滤拦截。detector_class=url_filter 而不是 waf —— "
             "验 web_exploit 那条按 waf 放宽的谓词**不该**把它捞进去。",
}


def rows():
    """★用与生产同一条构造路径(`config` → `Neo4jGraph`),不自己拼参数。

    第一版构造时一个参数都没传 —— 而它要 3 个位置参数,而这**只在真机上才炸**:
    本地没有图,任何"能不能连上"的问题都测不出来。同一类错误上一版刚犯过一次
    (`run_cypher` 传了 dict),说明光钉一个方法签名不够,得钉**整条构造路径**。
    """
    from soc_agent.config import Config
    from soc_agent.graph.client import Neo4jGraph
    cfg = Config.from_env()
    g = Neo4jGraph(cfg.neo4j_uri, cfg.neo4j_user, cfg.neo4j_password, cfg.neo4j_database)
    try:
        return g.run_cypher(Q)          # ★run_cypher 是 **params 不是 dict —— 传 {} 会 TypeError
    finally:
        try:
            g.close()
        except Exception:
            pass


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--uids", action="store_true", help="只吐 uid(一行一个),给 shell 循环用")
    a = ap.parse_args(argv)
    rs = rows()
    if a.uids:
        for r in rs:
            print(r["uid"])
        return 0 if rs else 3
    print(f"演练图里共 {len(rs)} 条告警(图 {os.environ.get('NEO4J_URI', '?')})\n")
    for i, r in enumerate(rs, 1):
        print(f"[{i}] {r['rule']}  ({r['source']} / {r['cls']})")
        print(f"    alert_uid   {r['uid']}")
        print(f"    描述        {r['desc']}")
        print(f"    严重度      规范={r['sev']} 原生={r['sev_native']} 刻度={r['sev_scale']}")
        print(f"    触发事件    activity={r['activity']} source={r['ev_source']} time={r['ev_time']}")
        why = WHY.get(str(r["rule"]))
        if why:
            print(f"    值得验什么  {why}")
        print()
    return 0 if rs else 3


if __name__ == "__main__":
    sys.exit(main())
