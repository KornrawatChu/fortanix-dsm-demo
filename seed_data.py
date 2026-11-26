"""
Fill the database with fake account applications - encrypted through DSM with
the CURRENT policy in config.yaml. Use before the re-encryption scene so the
job runs long enough to submit a form / press Ctrl+C while it is working.

    python seed_data.py          # 100 applications (~6 DSM calls each)
    python seed_data.py 30
"""
import sys
import time
from pathlib import Path

from dotenv import load_dotenv

load_dotenv(Path(__file__).resolve().parent / ".env")

import account_repository as repo  # noqa: E402
import mock_data  # noqa: E402
import settings  # noqa: E402
from crypto_service import FieldEncryptor  # noqa: E402
from dsm import create_client  # noqa: E402

n = int(sys.argv[1]) if len(sys.argv) > 1 else 100
db = repo.connect()
s = settings.load()
enc = FieldEncryptor(create_client(), s)
print(f"[{db.label}] seeding {n} applications with policy: key={s.key_name} mode={s.mode}")
t0 = time.perf_counter()
for i in range(1, n + 1):
    repo.save_application(db, enc, mock_data.applicant())
    print(f"\r  {i}/{n}", end="", flush=True)
print(f"\n  done in {time.perf_counter() - t0:.0f}s")
