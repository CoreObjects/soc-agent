"""watermark 游标存储:JSON state 文件 + 原子替换(增量 tail 的断点)。

- 每索引存 {sort(ES 原样返回的游标数组), updated_at, docs_ingested}。
- 写后检查点:一页写完 Neo4j 成功才 save;崩在半页 → 重启从上次 checkpoint 重读 → MERGE 幂等去重 → 不漏不重。
- 单写者、零依赖(stdlib);接口是 Watermark Protocol,将来多写者可换 SQLite。
"""
import json
import os
from datetime import datetime, timezone
from pathlib import Path


class JsonWatermark:
    def __init__(self, path):
        self._path = Path(path)

    def _read(self) -> dict:
        if not self._path.exists():
            return {}
        return json.loads(self._path.read_text(encoding="utf-8"))

    def load(self, index):
        """返回该索引上次的 sort 游标数组;无则 None。"""
        return self._read().get(index, {}).get("sort")

    def save(self, index, sort, *, count: int = 0) -> None:
        """原子写:更新该索引游标 + 累加 docs_ingested。"""
        data = self._read()
        entry = data.get(index, {})
        entry["sort"] = sort
        entry["updated_at"] = datetime.now(timezone.utc).isoformat()
        entry["docs_ingested"] = entry.get("docs_ingested", 0) + count
        data[index] = entry
        self._atomic_write(data)

    def _atomic_write(self, data: dict) -> None:
        tmp = str(self._path) + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, self._path)          # POSIX 原子 rename(server1 Ubuntu 保证)
