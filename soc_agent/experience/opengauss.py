"""openGauss(server2 原生 5432,非 docker)持久化:经验库 + 案例库。psycopg2 走 PG 协议。

JSON 字段用 **text** 存(json.dumps/loads),避开 jsonb 跨版本方言;查询只按标量列(skill/status/kind)。
psycopg2 惰性 import(dev 机不装也能 import 本模块跑其余单测)。连接/建表失败 → 抛异常,
调用方(build)捕获后降级 InMemory(经验层=永远走 LLM,零 regression)。不赌 ON CONFLICT 方言。
"""
import json
from types import SimpleNamespace
from uuid import uuid4

from ..forensics import Finding
from .cases import Case, CaseStore
from .store import EXP_STATUSES, Experience, ExperienceStore

_EXP_COLS = ("exp_id, skill, kind, verdict, fingerprint, rule, playbook, status, "
             "hit_count, override_count, origin_case_id, origin_verdict_id, note, created_by, created_at, "
             "coverage_sig")


def _connect(cfg):
    import psycopg2                       # 惰性:dev 机无 psycopg2 也能跑其余单测
    conn = psycopg2.connect(host=cfg.og_host, port=cfg.og_port, dbname=cfg.og_database,
                            user=cfg.og_user, password=cfg.og_password, connect_timeout=10)
    # ★任何查询/写入 15s 不返回就报错(psycopg2 默认无超时,遇锁/坏连接会无限挂)。经验读写本该毫秒级。
    with conn.cursor() as cur:
        cur.execute("SET statement_timeout = 15000")
        # ★★openGauss 有 `session_timeout`,**默认 600 秒**(PostgreSQL 没有这个参数)。
        #   poller 是常驻进程,只要 10 分钟没做经验读写,服务端就把这条会话掐掉。
        #   会话级关掉它;这是双保险 —— 真正的保障是下面 LiveConn 的自动重连。
        try:
            cur.execute("SET session_timeout = 0")
        except Exception:                  # 别的 PG 兼容库没这个参数 —— 不是错,跳过
            conn.rollback()
    conn.commit()
    return conn


class LiveConn:
    """**带健康检查 + 自动重连**的连接门面。看起来像 psycopg2 连接(cursor/commit/…),
    所以下面所有 Store **一行都不用改**。

    ★为什么必须有它(这是生产上"高斯经常连不上"的真因):
      原来 `open_stores` 在**进程启动时连一次**,三个 Store 共用那一条连接用一辈子,
      而全模块**没有任何**重连/健康检查/InterfaceError 处理(改之前 grep 命中数 = 0)。
      配上 openGauss 那个 600 秒 `session_timeout`,后果是:
      poller 启动后只要有 10 分钟没做经验读写,连接就被服务端掐掉,
      **此后每一次经验读写都抛 `InterfaceError: connection already closed`,直到有人重启 poller**。

    ★而它一直没被发现,是因为**它的表现和"没有匹配的经验"一模一样** ——
      经验层查不到就走大模型,链路照常出结论,只是复用永远命中不了、蒸馏也永远落不了地。
      对得上现网的数字:`experience` 只有 28 行(约等于启动后头 10 分钟写进去的那些),
      而 `cases` 有 10.3 万(那是批处理脚本写的,每次新进程新连接,不受影响)。

    ★重连失败**大声抛**,不静默降级 —— 静默降级正是上面那个"查不到 == 没有"的老问题。
    """

    def __init__(self, cfg):
        self._cfg = cfg
        self._conn = None
        self.reconnects = 0          # 可观测:被掐掉过几次(现网这个数应该 > 0)

    def _live(self):
        if self._conn is None:
            self._conn = _connect(self._cfg)
            return self._conn
        try:
            with self._conn.cursor() as cur:      # 本地 SELECT 1,亚毫秒;经验读写频率低,值得每次探
                cur.execute("SELECT 1")
            return self._conn
        except Exception:
            try:
                self._conn.close()
            except Exception:
                pass
            self._conn = None
            self._conn = _connect(self._cfg)      # 连不上就抛 —— 大声,不静默
            self.reconnects += 1
            return self._conn

    # --- 让它长得像一条连接(Store 代码零改动) ---
    def cursor(self, *a, **kw):
        return self._live().cursor(*a, **kw)

    def commit(self):
        if self._conn is not None:
            self._conn.commit()

    def rollback(self):
        if self._conn is not None:
            try:
                self._conn.rollback()
            except Exception:
                pass

    def close(self):
        if self._conn is not None:
            try:
                self._conn.close()
            finally:
                self._conn = None

    @property
    def closed(self):
        return self._conn is None or getattr(self._conn, "closed", 1)


def ddl(schema) -> list:
    return [
        f"CREATE SCHEMA IF NOT EXISTS {schema}",
        f"""CREATE TABLE IF NOT EXISTS {schema}.experience (
              exp_id varchar(64) PRIMARY KEY, skill varchar(128) NOT NULL, kind varchar(32) NOT NULL,
              verdict varchar(32) NOT NULL, fingerprint text, rule text, playbook text,
              status varchar(16) NOT NULL DEFAULT 'active', hit_count integer NOT NULL DEFAULT 0,
              override_count integer NOT NULL DEFAULT 0, origin_case_id varchar(64),
              origin_verdict_id varchar(64), note text,
              created_by varchar(128), created_at timestamptz DEFAULT now())""",
        # 迁移:已存在的旧表补列(CREATE IF NOT EXISTS 不会改老表)。幂等。
        f"ALTER TABLE {schema}.experience ADD COLUMN IF NOT EXISTS note text",
        f"ALTER TABLE {schema}.experience ADD COLUMN IF NOT EXISTS origin_verdict_id varchar(64)",
        # WP9:这条经验是在什么覆盖度条件下学到的。**可空** —— 存量行留空,
        #   而召回侧把"空"当作"未知、一律放行",不当作"不匹配"(否则一开分区开关
        #   16 万条存量沉淀会静默全部失配,不报错、只是从此再不召回)。
        f"ALTER TABLE {schema}.experience ADD COLUMN IF NOT EXISTS coverage_sig varchar(64)",
        f"CREATE INDEX IF NOT EXISTS ix_exp_skill_status ON {schema}.experience(skill, status)",
        f"""CREATE TABLE IF NOT EXISTS {schema}.cases (
              case_id varchar(64) PRIMARY KEY, skill varchar(128) NOT NULL, alert_uid varchar(128) NOT NULL,
              verdict varchar(32) NOT NULL, findings text, created_at timestamptz DEFAULT now())""",
        f"CREATE INDEX IF NOT EXISTS ix_cases_skill ON {schema}.cases(skill)",
        # 浅层判例语料(payload 签名反例回归用);source 作分区键
        f"""CREATE TABLE IF NOT EXISTS {schema}.payload_cases (
              case_id varchar(64) PRIMARY KEY, source varchar(128), alert_uid varchar(128) NOT NULL,
              verdict varchar(32) NOT NULL, raw text, rule_description text, rule_id varchar(128),
              severity varchar(64), technique_ids text, created_at timestamptz DEFAULT now())""",
        f"CREATE INDEX IF NOT EXISTS ix_pcases_source ON {schema}.payload_cases(source)",
    ]


def ensure_schema(conn, schema) -> None:
    with conn.cursor() as cur:
        for stmt in ddl(schema):
            cur.execute(stmt)
    conn.commit()


def _row_to_exp(row) -> Experience:
    (exp_id, skill, kind, verdict, fp, rule, pb, status, hc, oc, ocid, ovid, note, cb, ca,
     csig) = row
    return Experience(skill=skill, kind=kind, verdict=verdict,
                      fingerprint=json.loads(fp) if fp else {},
                      rule=json.loads(rule) if rule else None,
                      playbook=json.loads(pb) if pb else [],
                      status=status, hit_count=hc or 0, override_count=oc or 0,
                      origin_case_id=ocid, origin_verdict_id=ovid, note=note, created_by=cb,
                      created_at=str(ca) if ca else None, coverage_sig=csig or "", exp_id=exp_id)


class OpenGaussExperienceStore(ExperienceStore):
    def __init__(self, conn, schema):
        self.conn = conn
        self.t = f"{schema}.experience"

    def add(self, exp: Experience) -> str:
        with self.conn.cursor() as cur:
            cur.execute(
                f"INSERT INTO {self.t} (exp_id,skill,kind,verdict,fingerprint,rule,playbook,status,"
                "hit_count,override_count,origin_case_id,origin_verdict_id,note,created_by,"
                "coverage_sig) "
                "VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)",
                (exp.exp_id, exp.skill, exp.kind, exp.verdict,
                 json.dumps(exp.fingerprint, ensure_ascii=False),
                 json.dumps(exp.rule, ensure_ascii=False) if exp.rule is not None else None,
                 json.dumps(exp.playbook, ensure_ascii=False),
                 exp.status, exp.hit_count, exp.override_count, exp.origin_case_id,
                 exp.origin_verdict_id, exp.note, exp.created_by, exp.coverage_sig or None))
        self.conn.commit()
        return exp.exp_id

    def get(self, exp_id: str):
        with self.conn.cursor() as cur:
            cur.execute(f"SELECT {_EXP_COLS} FROM {self.t} WHERE exp_id=%s", (exp_id,))
            row = cur.fetchone()
        return _row_to_exp(row) if row else None

    def all(self) -> list:
        with self.conn.cursor() as cur:
            cur.execute(f"SELECT {_EXP_COLS} FROM {self.t}")
            rows = cur.fetchall()
        return [_row_to_exp(r) for r in rows]

    def active_for_skill(self, skill: str) -> list:
        with self.conn.cursor() as cur:
            cur.execute(f"SELECT {_EXP_COLS} FROM {self.t} WHERE skill=%s AND status='active'", (skill,))
            rows = cur.fetchall()
        return [_row_to_exp(r) for r in rows]

    def bump_hit(self, exp_id: str) -> None:
        with self.conn.cursor() as cur:
            cur.execute(f"UPDATE {self.t} SET hit_count=hit_count+1 WHERE exp_id=%s", (exp_id,))
        self.conn.commit()

    def bump_override(self, exp_id: str) -> None:
        with self.conn.cursor() as cur:
            cur.execute(f"UPDATE {self.t} SET override_count=override_count+1 WHERE exp_id=%s", (exp_id,))
        self.conn.commit()

    def set_status(self, exp_id: str, status: str) -> None:
        if status not in EXP_STATUSES:
            raise ValueError(f"未知 status:{status!r}")
        with self.conn.cursor() as cur:
            cur.execute(f"UPDATE {self.t} SET status=%s WHERE exp_id=%s", (status, exp_id))
        self.conn.commit()


class OpenGaussCaseStore(CaseStore):
    def __init__(self, conn, schema):
        self.conn = conn
        self.t = f"{schema}.cases"

    def add(self, case: Case) -> None:
        with self.conn.cursor() as cur:
            cur.execute(
                f"INSERT INTO {self.t} (case_id,skill,alert_uid,verdict,findings) VALUES (%s,%s,%s,%s,%s)",
                (uuid4().hex, case.skill, case.alert_uid, case.verdict,
                 json.dumps([f.to_dict() for f in case.findings], ensure_ascii=False)))
        self.conn.commit()

    def by_skill(self, skill: str) -> list:
        with self.conn.cursor() as cur:
            cur.execute(f"SELECT skill, alert_uid, verdict, findings FROM {self.t} WHERE skill=%s", (skill,))
            rows = cur.fetchall()
        out = []
        for sk, uid, verdict, fj in rows:
            findings = [Finding.from_dict(d) for d in (json.loads(fj) if fj else [])]
            out.append(Case(skill=sk, alert_uid=uid, verdict=verdict, findings=findings))
        return out


class OpenGaussPayloadCaseStore:
    """浅层判例语料(openGauss);for_source 取某源全部判例(sig_sediment 内部再筛反例 verdict)。
    返回 duck-typed 行(payload_match/sig_sediment 只按属性读)——不 import cascade,避免层反依赖。"""

    def __init__(self, conn, schema):
        self.conn = conn
        self.t = f"{schema}.payload_cases"

    def add(self, case) -> None:
        tids = getattr(case, "technique_ids", None) or []
        sev = getattr(case, "severity", None)
        with self.conn.cursor() as cur:
            cur.execute(
                f"INSERT INTO {self.t} (case_id,source,alert_uid,verdict,raw,rule_description,"
                "rule_id,severity,technique_ids) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)",
                (uuid4().hex, (getattr(case, "source", None) or "shallow"), case.alert_uid, case.verdict,
                 getattr(case, "raw", None), getattr(case, "rule_description", None),
                 getattr(case, "rule_id", None), (str(sev) if sev is not None else None),
                 json.dumps(tids, ensure_ascii=False)))
        self.conn.commit()

    def for_source(self, source) -> list:
        with self.conn.cursor() as cur:
            cur.execute(f"SELECT alert_uid,source,verdict,raw,rule_description,rule_id,severity,"
                        f"technique_ids FROM {self.t} WHERE source=%s", (source or "shallow",))
            rows = cur.fetchall()
        return [SimpleNamespace(alert_uid=uid, source=src, verdict=vd, raw=raw, rule_description=rd,
                                rule_id=rid, severity=sev, technique_ids=json.loads(tj) if tj else [])
                for (uid, src, vd, raw, rd, rid, sev, tj) in rows]


def open_stores(cfg):
    """连接 openGauss + 建表,返回 (ExperienceStore, CaseStore, PayloadCaseStore)。失败抛异常 → 降级 InMemory。"""
    # ★用 LiveConn 而不是裸连接:常驻进程 + openGauss 600 秒 session_timeout =
    #   一条永不重连的长连接必然会死,而死后的表现与"没有匹配的经验"无法区分。
    conn = LiveConn(cfg)
    ensure_schema(conn, cfg.og_schema)
    return (OpenGaussExperienceStore(conn, cfg.og_schema), OpenGaussCaseStore(conn, cfg.og_schema),
            OpenGaussPayloadCaseStore(conn, cfg.og_schema))


def wipe(cfg):
    """清空经验库 + 案例库(reset_pristine 用)。返回 (exp_before, cases_before)。"""
    conn = _connect(cfg)
    ensure_schema(conn, cfg.og_schema)                     # 确保表在(否则 count 报错)
    s = cfg.og_schema
    with conn.cursor() as cur:
        cur.execute(f"SELECT count(*) FROM {s}.experience")
        ne = cur.fetchone()[0]
        cur.execute(f"SELECT count(*) FROM {s}.cases")
        nc = cur.fetchone()[0]
        cur.execute(f"DELETE FROM {s}.experience")
        cur.execute(f"DELETE FROM {s}.cases")
        cur.execute(f"DELETE FROM {s}.payload_cases")
    conn.commit()
    conn.close()
    return ne, nc
