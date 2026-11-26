"""
Show what is REALLY stored in the database - straight SQL, no app logic, no DSM call.

    python show_db.py            # one line per application: which key version (kid) protects it
    python show_db.py --raw      # full stored value of every encrypted column

(For the most convincing view, open the same table in DBeaver - see README.)
"""
import json
import sys
from pathlib import Path

from dotenv import load_dotenv

load_dotenv(Path(__file__).resolve().parent / ".env")
from account_repository import ENCRYPTED_FIELDS, TABLE, connect  # noqa: E402

db = connect()
rows = db.execute(f"SELECT * FROM {TABLE} ORDER BY id").fetchall()
if not rows:
    sys.exit(f"[{db.label}] No applications yet - submit the form first.")

print(f"\n[{db.label}]  SELECT ref_no, first_name, national_id FROM {TABLE};\n")
print(f"{'ref_no':<20} {'name':<12} {'alg':<4} {'mode':<17} kid (key version in Fortanix DSM)")
print("-" * 100)
for r in rows:
    v = json.loads(r["national_id"])
    print(f"{r['ref_no']:<20} {r['first_name']:<12} {v.get('alg', 'AES'):<4} {v['mode']:<17} {v['kid']}")

if "--raw" in sys.argv:
    for r in rows:
        print(f"\n=== {r['ref_no']} ===")
        for f in ENCRYPTED_FIELDS:
            print(f"  {f:<15} {r[f]}")
print()
