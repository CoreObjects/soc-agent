"""openGauss 权威规则库适配(实现 PatternRepository 接口)。

psycopg2 走 TCP(openGauss PG 兼容,md5 认证)。★表放【soc_agent 自建的独立 schema】(它 owns soc 库 → 能建 schema),
不碰 public(openGauss 7.0/PG15+ 默认不给非 owner CREATE on public)→ 无需 omm/超管介入。
建表幂等;upsert 按 sig_hash 去重(SELECT→INSERT/UPDATE,不赌 ON CONFLICT 方言);模板整块 json/text 存取。
热读由 CachedPatternRepository 包外层。只用通用关系能力,换任何 PG 兼容库=换 DSN。
"""
import json
import re
from typing import List, Optional

from .rule import PatternRule
from .serialize import row_to_rule, rule_to_row

_COLS = ["sig_hash", "skill", "layer", "sig", "verdict_tmpl", "disp_tmpl", "status", "stats", "provenance"]
_IDENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


class OpenGaussPatternRepository:
    def __init__(self, host, port, dbname, user, password, schema="app", connect_timeout=10):
        import psycopg2                       # 延迟导入:本地/单测不装驱动也能 import 本模块
        self._psycopg2 = psycopg2
        if not _IDENT.match(schema):
            raise ValueError(f"非法 schema 名: {schema!r}")
        self._schema = schema
        self._table = f"{schema}.patterns"
        self._dsn = dict(host=host, port=int(port), dbname=dbname, user=user,
                         password=password, connect_timeout=connect_timeout)
        self._conn = None
        self._connect()
        self._ensure_schema()

    # ---- 连接 ----
    def _connect(self):
        self._conn = self._psycopg2.connect(**self._dsn)
        self._conn.autocommit = True

    def _cur(self):
        try:
            if self._conn is None or self._conn.closed:
                self._connect()
            return self._conn.cursor()
        except self._psycopg2.OperationalError:
            self._connect()                   # 断线重连一次
            return self._conn.cursor()

    def _exec_ok(self, sql):
        """执行,吞掉"已存在/不支持 IF NOT EXISTS"等非致命错(autocommit,不会污染后续)。"""
        try:
            with self._cur() as cur:
                cur.execute(sql)
        except Exception:
            pass

    def _ensure_schema(self):
        self._exec_ok(f"CREATE SCHEMA {self._schema}")           # soc_agent owns db → 可建;已存在则忽略
        with self._cur() as cur:                                 # 表必须成功(不吞错,失败即暴露权限问题)
            cur.execute(
                f"CREATE TABLE IF NOT EXISTS {self._table} ("
                "  sig_hash     VARCHAR(64) PRIMARY KEY,"
                "  skill        VARCHAR(128) NOT NULL,"
                "  layer        VARCHAR(32)  NOT NULL,"
                "  sig          TEXT NOT NULL,"
                "  verdict_tmpl TEXT NOT NULL,"
                "  disp_tmpl    TEXT NOT NULL,"
                "  status       VARCHAR(16) NOT NULL DEFAULT 'pending',"
                "  stats        TEXT,"
                "  provenance   TEXT,"
                "  created_at   TIMESTAMP DEFAULT now(),"
                "  updated_at   TIMESTAMP DEFAULT now())")
        self._exec_ok(f"CREATE INDEX IF NOT EXISTS idx_patterns_status ON {self._table}(status)")

    # ---- 接口 ----
    def upsert(self, rule: PatternRule) -> PatternRule:
        row = rule_to_row(rule)
        with self._cur() as cur:
            cur.execute(f"SELECT stats FROM {self._table} WHERE sig_hash=%s", (row["sig_hash"],))
            hit = cur.fetchone()
            if hit is None:                   # 新规则:hit_count 至少 1(对齐内存 fake)
                stats = dict(rule.stats or {}); stats["hit_count"] = max(stats.get("hit_count", 0), 1)
                row["stats"] = json.dumps(stats, ensure_ascii=False)
                cur.execute(
                    f"INSERT INTO {self._table} (" + ",".join(_COLS) + ") VALUES (" + ",".join(["%s"] * len(_COLS)) + ")",
                    tuple(row[c] for c in _COLS))
            else:                             # 已存在:只 bump hit_count(首铸定模板,复用不覆盖)
                stats = json.loads(hit[0]) if hit[0] else {}
                stats["hit_count"] = stats.get("hit_count", 0) + 1
                cur.execute(f"UPDATE {self._table} SET stats=%s, updated_at=now() WHERE sig_hash=%s",
                            (json.dumps(stats, ensure_ascii=False), row["sig_hash"]))
        return self.get(rule.sig_hash) or rule

    def find_active(self, sig_hash: str) -> Optional[PatternRule]:
        return self._fetch_one(
            f"SELECT {','.join(_COLS)} FROM {self._table} WHERE sig_hash=%s AND status='active'", (sig_hash,))

    def get(self, sig_hash: str) -> Optional[PatternRule]:
        return self._fetch_one(f"SELECT {','.join(_COLS)} FROM {self._table} WHERE sig_hash=%s", (sig_hash,))

    def set_status(self, sig_hash: str, status: str) -> None:
        with self._cur() as cur:
            cur.execute(f"UPDATE {self._table} SET status=%s, updated_at=now() WHERE sig_hash=%s", (status, sig_hash))

    def list_pending(self) -> List[PatternRule]:
        with self._cur() as cur:
            cur.execute(f"SELECT {','.join(_COLS)} FROM {self._table} WHERE status='pending' ORDER BY created_at")
            return [row_to_rule(dict(zip(_COLS, r))) for r in cur.fetchall()]

    def _fetch_one(self, sql, params) -> Optional[PatternRule]:
        with self._cur() as cur:
            cur.execute(sql, params)
            r = cur.fetchone()
            return row_to_rule(dict(zip(_COLS, r))) if r else None

    def close(self):
        if self._conn is not None and not self._conn.closed:
            self._conn.close()
