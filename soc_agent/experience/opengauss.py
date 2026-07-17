"""openGauss(server2 原生 5432,非 docker)持久化:经验库 + 案例库。psycopg2 走 PG 协议。

JSON 字段用 **text** 存(json.dumps/loads),避开 jsonb 跨版本方言;查询只按标量列(skill/status/kind)。
psycopg2 惰性 import(dev 机不装也能 import 本模块跑其余单测)。连接/建表失败 → 抛异常,
调用方(build)捕获后降级 InMemory(经验层=永远走 LLM,零 regression)。不赌 ON CONFLICT 方言。
"""
import json
from uuid import uuid4

from ..forensics import Finding
from .cases import Case, CaseStore
from .store import EXP_STATUSES, Experience, ExperienceStore

_EXP_COLS = ("exp_id, skill, kind, verdict, fingerprint, rule, playbook, status, "
             "hit_count, override_count, origin_case_id, created_by, created_at")


def _connect(cfg):
    import psycopg2                       # 惰性:dev 机无 psycopg2 也能跑其余单测
    return psycopg2.connect(host=cfg.og_host, port=cfg.og_port, dbname=cfg.og_database,
                            user=cfg.og_user, password=cfg.og_password)


def ddl(schema) -> list:
    return [
        f"CREATE SCHEMA IF NOT EXISTS {schema}",
        f"""CREATE TABLE IF NOT EXISTS {schema}.experience (
              exp_id varchar(64) PRIMARY KEY, skill varchar(128) NOT NULL, kind varchar(32) NOT NULL,
              verdict varchar(32) NOT NULL, fingerprint text, rule text, playbook text,
              status varchar(16) NOT NULL DEFAULT 'active', hit_count integer NOT NULL DEFAULT 0,
              override_count integer NOT NULL DEFAULT 0, origin_case_id varchar(64),
              created_by varchar(128), created_at timestamptz DEFAULT now())""",
        f"CREATE INDEX IF NOT EXISTS ix_exp_skill_status ON {schema}.experience(skill, status)",
        f"""CREATE TABLE IF NOT EXISTS {schema}.cases (
              case_id varchar(64) PRIMARY KEY, skill varchar(128) NOT NULL, alert_uid varchar(128) NOT NULL,
              verdict varchar(32) NOT NULL, findings text, created_at timestamptz DEFAULT now())""",
        f"CREATE INDEX IF NOT EXISTS ix_cases_skill ON {schema}.cases(skill)",
    ]


def ensure_schema(conn, schema) -> None:
    with conn.cursor() as cur:
        for stmt in ddl(schema):
            cur.execute(stmt)
    conn.commit()


def _row_to_exp(row) -> Experience:
    (exp_id, skill, kind, verdict, fp, rule, pb, status, hc, oc, ocid, cb, ca) = row
    return Experience(skill=skill, kind=kind, verdict=verdict,
                      fingerprint=json.loads(fp) if fp else {},
                      rule=json.loads(rule) if rule else None,
                      playbook=json.loads(pb) if pb else [],
                      status=status, hit_count=hc or 0, override_count=oc or 0,
                      origin_case_id=ocid, created_by=cb, created_at=str(ca) if ca else None, exp_id=exp_id)


class OpenGaussExperienceStore(ExperienceStore):
    def __init__(self, conn, schema):
        self.conn = conn
        self.t = f"{schema}.experience"

    def add(self, exp: Experience) -> str:
        with self.conn.cursor() as cur:
            cur.execute(
                f"INSERT INTO {self.t} (exp_id,skill,kind,verdict,fingerprint,rule,playbook,status,"
                "hit_count,override_count,origin_case_id,created_by) "
                "VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)",
                (exp.exp_id, exp.skill, exp.kind, exp.verdict,
                 json.dumps(exp.fingerprint, ensure_ascii=False),
                 json.dumps(exp.rule, ensure_ascii=False) if exp.rule is not None else None,
                 json.dumps(exp.playbook, ensure_ascii=False),
                 exp.status, exp.hit_count, exp.override_count, exp.origin_case_id, exp.created_by))
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


def open_stores(cfg):
    """连接 openGauss + 建表,返回 (ExperienceStore, CaseStore)。失败抛异常 → 调用方降级 InMemory。"""
    conn = _connect(cfg)
    ensure_schema(conn, cfg.og_schema)
    return OpenGaussExperienceStore(conn, cfg.og_schema), OpenGaussCaseStore(conn, cfg.og_schema)


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
    conn.commit()
    conn.close()
    return ne, nc
