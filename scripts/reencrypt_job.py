"""
Batch re-encryption: bring every stored value up to the CURRENT policy in config.yaml.

Safe to stop and re-run: each value carries its own metadata, so the job only
touches values that are not current, and the app keeps working during migration.

    python scripts/reencrypt_job.py             # account_applications (the form app)
    python scripts/reencrypt_job.py customers   # table used by the engineer console
"""
from __future__ import annotations

import sys as _sys
from pathlib import Path as _Path
_sys.path.insert(0, str(_Path(__file__).resolve().parents[1]))  # project root on the import path

from typing import Callable, Optional, Sequence

from dsm_crypto.crypto_service import FieldEncryptor, describe, is_current


def current_kid(enc: FieldEncryptor) -> Optional[str]:
    name = enc.s.key_name if enc.s.pattern == "direct" else enc.s.kek_name
    k = enc.dsm.get_key(name)
    return k.kid if k else None


def run(db, enc: FieldEncryptor, progress: Optional[Callable[[int, int], None]] = None,
        table: str = "account_applications", fields: Optional[Sequence[str]] = None) -> dict:
    if fields is None:
        from app.account_repository import ENCRYPTED_FIELDS
        fields = ENCRYPTED_FIELDS
    kid = current_kid(enc)
    rows = db.execute(f"SELECT id, {', '.join(fields)} FROM {table} ORDER BY id").fetchall()
    stats = {"rows": len(rows), "rows_processed": 0, "values_checked": 0,
             "values_reencrypted": 0, "already_current": 0, "interrupted": False}
    try:
        for i, row in enumerate(rows, 1):
            updates = {}
            for f in fields:
                if is_current(row[f], enc.s, kid):
                    stats["already_current"] += 1
                else:
                    plain = enc.reveal(row[f])          # decrypt with the OLD key/algorithm (from metadata)
                    updates[f] = enc.protect(plain)     # encrypt with the NEW policy (from config.yaml)
            if updates:
                sets = ", ".join(f"{f}=?" for f in updates)
                db.execute(f"UPDATE {table} SET {sets} WHERE id=?", (*updates.values(), row["id"]))
                db.commit()                             # one row at a time -> safe to stop at any moment
                stats["values_reencrypted"] += len(updates)
            stats["values_checked"] += len(fields)
            stats["rows_processed"] = i
            if progress:
                progress(i, len(rows))
    except KeyboardInterrupt:
        # Ctrl+C: the row in flight was never written, every finished row is committed.
        stats["interrupted"] = True
    return stats


def policy_summary(db, table: str, fields: Sequence[str]) -> dict[str, int]:
    out: dict[str, int] = {}
    for row in db.execute(f"SELECT {', '.join(fields)} FROM {table}"):
        for f in fields:
            d = describe(row[f])
            label = f"{d['algorithm']}  key={d['key_name']}  kid={d['kid'][:8]}"
            out[label] = out.get(label, 0) + 1
    return out


if __name__ == "__main__":
    import sys

    from dotenv import load_dotenv

    from dsm_crypto import settings
    from dsm_crypto.dsm import create_client

    from pathlib import Path
    load_dotenv(Path(__file__).resolve().parents[1] / ".env")
    table = sys.argv[1] if len(sys.argv) > 1 else "account_applications"
    if table == "account_applications":
        from app import account_repository as repo
        db, fields = repo.connect(), repo.ENCRYPTED_FIELDS
    else:
        from extras import customer_repository as repo
        db, fields = repo.connect(), repo.SENSITIVE

    def show(title: str) -> None:
        print(title)
        for label, count in policy_summary(db, table, fields).items():
            print(f"  {count:>5} values  {label}")

    def bar(i: int, n: int) -> None:
        filled = int(30 * i / n) if n else 30
        print(f"\r  [{'#' * filled}{'.' * (30 - filled)}] {i}/{n} rows", end="", flush=True)

    s = settings.load()
    print(f"\nTarget policy (config.yaml): pattern={s.pattern}  key={s.key_name}  mode={s.mode}")
    show("Before:")
    print("Re-encrypting (Ctrl+C to stop - safe, run again to continue):")
    r = run(db, FieldEncryptor(create_client(), s), bar, table=table, fields=fields)
    print()
    if r["interrupted"]:
        print(f"\n  STOPPED by user after {r['rows_processed']}/{r['rows']} rows - "
              f"{r['values_reencrypted']} values migrated, nothing half-written.")
        print("  Run this job again to continue where it left off.")
    else:
        print(f"\n  Done: {r['values_reencrypted']} values re-encrypted, "
              f"{r['already_current']} already on the current policy.")
    show("After:")
