"""
Tiny database adapter: PostgreSQL (DATABASE_URL in .env) or SQLite (fallback / tests).

Repository code writes SQL once with '?' placeholders; this converts them for PostgreSQL.
Nothing here knows about encryption - the database only ever receives ciphertext.
"""
from __future__ import annotations

import os
import sqlite3
from pathlib import Path
from typing import Any, Iterable


class Db:
    def __init__(self, conn: Any, kind: str, label: str, url: str | None = None) -> None:
        self.conn = conn
        self.kind = kind          # "postgres" | "sqlite"
        self.label = label        # shown in the UI / scripts (no password)
        self._url = url           # kept so we can reconnect

    def _reconnect(self) -> None:
        try:
            self.conn.close()
        except Exception:
            pass
        self.conn = _pg_connect(self._url)

    def execute(self, sql: str, params: Iterable = ()):
        if self.kind != "postgres":
            return self.conn.execute(sql, tuple(params))
        import psycopg
        sql = sql.replace("?", "%s")
        if self.conn.closed:
            self._reconnect()
        try:
            return self.conn.execute(sql, tuple(params))
        except psycopg.OperationalError:
            # Connection dropped (e.g. Postgres container restarted) -> reconnect and retry once.
            self._reconnect()
            return self.conn.execute(sql, tuple(params))

    def commit(self) -> None:
        self.conn.commit()


def _pg_connect(url: str):
    import psycopg
    from psycopg.rows import dict_row
    return psycopg.connect(url, row_factory=dict_row, autocommit=True, connect_timeout=5)


def connect(target: str | Path | None = None) -> Db:
    """target: a SQLite file path, a postgresql:// URL, or None -> DATABASE_URL / default SQLite."""
    if target is None:
        target = os.getenv("DATABASE_URL") or Path(__file__).resolve().parents[1] / "data" / "bank.db"
    if isinstance(target, str) and target.startswith("postgres"):
        conn = _pg_connect(target)
        info = conn.info
        return Db(conn, "postgres", f"PostgreSQL {info.host}:{info.port}/{info.dbname}", url=target)
    path = Path(target)
    path.parent.mkdir(exist_ok=True)
    conn = sqlite3.connect(path, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return Db(conn, "sqlite", f"SQLite {path.name}")
