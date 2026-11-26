"""
Batch re-encryption: bring every stored value up to the CURRENT policy in config.yaml.

Safe to stop and re-run: each value carries its own metadata, so the job only
touches values that are not current, and the app keeps working during migration.

    python reencrypt_job.py                 # account_applications (the form app)
    python reencrypt_job.py customers       # table used by the engineer console
"""
from __future__ import annotations

from typing import Callable, Optional, Sequence

from crypto_service import FieldEncryptor, describe, is_current


def current_kid(enc: FieldEncryptor) -> Optional[str]:
    name = enc.s.key_name if enc.s.pattern == "direct" else enc.s.kek_name
    k = enc.dsm.get_key(name)
    return k.kid if k else None


def run(db, enc: FieldEncryptor, progress: Optional[Callable[[int, int], None]] = None,
        table: str = "customers", fields: Optional[Sequence[str]] = None) -> dict:
    if fields is None:
        from customer_repository import SENSITIVE
        fields = SENSITIVE
    kid = current_kid(enc)
    rows = db.execute(f"SELECT id, {', '.join(fields)} FROM {table}").fetchall()
    stats = {"rows": len(rows), "values_checked": 0, "values_reencrypted": 0, "already_current": 0}
    for i, row in enumerate(rows, 1):
        updates = {}
        for f in fields:
            stats["values_checked"] += 1
            if is_current(row[f], enc.s, kid):
                stats["already_current"] += 1
                continue
            plain = enc.reveal(row[f])          # decrypt with the OLD key/algorithm (from metadata)
            updates[f] = enc.protect(plain)     # encrypt with the NEW policy (from config.yaml)
        if updates:
            sets = ", ".join(f"{f}=?" for f in updates)
            db.execute(f"UPDATE {table} SET {sets} WHERE id=?", (*updates.values(), row["id"]))
            stats["values_reencrypted"] += len(updates)
        if progress:
            progress(i, len(rows))
    db.commit()
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

    import settings
    from dsm import create_client

    load_dotenv()
    table = sys.argv[1] if len(sys.argv) > 1 else "account_applications"
    if table == "account_applications":
        import account_repository as repo
        db, fields = repo.connect(), repo.ENCRYPTED_FIELDS
    else:
        import customer_repository as repo
        db, fields = repo.connect(), repo.SENSITIVE

    s = settings.load()
    print(f"Target policy (config.yaml): pattern={s.pattern} key={s.key_name} mode={s.mode}")
    print("Before:", *[f"  {v:>4} values  {k}" for k, v in policy_summary(db, table, fields).items()], sep="\n")
    result = run(db, FieldEncryptor(create_client(), s), lambda i, n: print(f"\r  re-encrypting {i}/{n}", end=""),
                 table=table, fields=fields)
    print("\n", result)
    print("After:", *[f"  {v:>4} values  {k}" for k, v in policy_summary(db, table, fields).items()], sep="\n")
