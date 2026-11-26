"""
BUSINESS CODE - the customer data access layer.

Notice what is NOT here: no algorithm, no key, no mode, no DSM URL.
This file did not change in any of the algorithm-change scenarios.
"""
from __future__ import annotations

import sqlite3
from datetime import datetime
from pathlib import Path

from crypto_service import FieldEncryptor

DB_PATH = Path(__file__).resolve().parent / "data" / "bank.db"
SENSITIVE = ("national_id", "account_no", "phone")


def connect(path: Path = DB_PATH) -> sqlite3.Connection:
    Path(path).parent.mkdir(exist_ok=True)
    db = sqlite3.connect(path, check_same_thread=False)
    db.row_factory = sqlite3.Row
    db.execute("""CREATE TABLE IF NOT EXISTS customers (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        full_name   TEXT NOT NULL,
        national_id TEXT NOT NULL,   -- encrypted
        account_no  TEXT NOT NULL,   -- encrypted
        phone       TEXT NOT NULL,   -- encrypted
        branch      TEXT,
        updated_at  TEXT)""")
    return db


def add_customer(db, enc: FieldEncryptor, c: dict) -> int:
    cur = db.execute(
        "INSERT INTO customers (full_name, national_id, account_no, phone, branch, updated_at) "
        "VALUES (?,?,?,?,?,?)",
        (c["full_name"], enc.protect(c["national_id"]), enc.protect(c["account_no"]),
         enc.protect(c["phone"]), c.get("branch"), datetime.now().isoformat(timespec="seconds")))
    db.commit()
    return cur.lastrowid


def list_raw(db) -> list[dict]:
    """Exactly what a DBA / attacker with DB access sees."""
    return [dict(r) for r in db.execute("SELECT * FROM customers ORDER BY id")]


def get_customer(db, enc: FieldEncryptor, cid: int) -> dict:
    r = dict(db.execute("SELECT * FROM customers WHERE id=?", (cid,)).fetchone())
    for f in SENSITIVE:
        r[f] = enc.reveal(r[f])
    return r


def clear(db) -> None:
    db.execute("DELETE FROM customers")
    db.execute("DELETE FROM sqlite_sequence WHERE name='customers'")
    db.commit()
