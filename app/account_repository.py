"""
BUSINESS CODE - account-opening applications (data access layer).

This is what a normal bank application looks like after adopting Fortanix DSM:
it calls enc.protect() before INSERT and enc.reveal() after SELECT. Nothing else.
No algorithm, no key, no mode, no DSM URL appears in this file.
"""
from __future__ import annotations

import secrets
from datetime import datetime
from pathlib import Path

from dsm_crypto import database
from dsm_crypto.crypto_service import FieldEncryptor

TABLE = "account_applications"

# Columns holding PII -> stored encrypted. Everything else stays plaintext.
ENCRYPTED_FIELDS = ("national_id", "date_of_birth", "mobile", "email", "address", "monthly_income")


def connect(target: str | Path | None = None) -> database.Db:
    """PostgreSQL when DATABASE_URL is set in .env, otherwise a local SQLite file."""
    db = database.connect(target)
    pk = "SERIAL PRIMARY KEY" if db.kind == "postgres" else "INTEGER PRIMARY KEY AUTOINCREMENT"
    db.execute(f"""CREATE TABLE IF NOT EXISTS {TABLE} (
        id             {pk},
        ref_no         TEXT UNIQUE NOT NULL,
        title          TEXT,
        first_name     TEXT NOT NULL,
        last_name      TEXT NOT NULL,
        national_id    TEXT NOT NULL,   -- encrypted
        date_of_birth  TEXT NOT NULL,   -- encrypted
        mobile         TEXT NOT NULL,   -- encrypted
        email          TEXT NOT NULL,   -- encrypted
        address        TEXT NOT NULL,   -- encrypted
        occupation     TEXT,
        monthly_income TEXT NOT NULL,   -- encrypted
        account_type   TEXT NOT NULL,
        created_at     TEXT NOT NULL)""")
    db.commit()
    return db


def save_application(db, enc: FieldEncryptor, form: dict) -> str:
    """Store a new application. PII is encrypted BEFORE it reaches the database."""
    ref_no = "APP-" + datetime.now().strftime("%y%m%d") + "-" + secrets.token_hex(3).upper()
    db.execute(
        f"""INSERT INTO {TABLE} (ref_no, title, first_name, last_name, national_id, date_of_birth,
            mobile, email, address, occupation, monthly_income, account_type, created_at)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (ref_no, form["title"], form["first_name"], form["last_name"],
         enc.protect(form["national_id"]),        # --> Fortanix DSM
         enc.protect(form["date_of_birth"]),      # --> Fortanix DSM
         enc.protect(form["mobile"]),             # --> Fortanix DSM
         enc.protect(form["email"]),              # --> Fortanix DSM
         enc.protect(form["address"]),            # --> Fortanix DSM
         form.get("occupation", ""),
         enc.protect(form["monthly_income"]),     # --> Fortanix DSM
         form["account_type"], datetime.now().isoformat(timespec="seconds")))
    db.commit()
    return ref_no


def list_applications(db) -> list[dict]:
    """Raw rows exactly as stored (what a DBA / backup / attacker would see)."""
    return [dict(r) for r in db.execute(f"SELECT * FROM {TABLE} ORDER BY id DESC")]


def get_application(db, enc: FieldEncryptor, ref_no: str) -> dict | None:
    """Authorised read: decrypt PII through DSM."""
    row = db.execute(f"SELECT * FROM {TABLE} WHERE ref_no=?", (ref_no,)).fetchone()
    if row is None:
        return None
    app = dict(row)
    for field in ENCRYPTED_FIELDS:
        app[field] = enc.reveal(app[field])       # <-- Fortanix DSM
    return app


def get_raw(db, ref_no: str) -> dict | None:
    row = db.execute(f"SELECT * FROM {TABLE} WHERE ref_no=?", (ref_no,)).fetchone()
    return dict(row) if row else None
