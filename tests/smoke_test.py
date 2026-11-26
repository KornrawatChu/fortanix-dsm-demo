"""
End-to-end check of every demo scenario.

    python tests/smoke_test.py            # offline, mock DSM
    python tests/smoke_test.py rest       # against real DSM (uses .env, creates demo keys)
"""
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from dotenv import load_dotenv  # noqa: E402

from app import mock_data  # noqa: E402
from scripts import reencrypt_job  # noqa: E402
from dsm_crypto.crypto_service import FieldEncryptor, describe  # noqa: E402
from extras.customer_repository import SENSITIVE, add_customer, connect, get_customer, list_raw  # noqa: E402
from dsm_crypto.dsm import create_client  # noqa: E402
from dsm_crypto.dsm.mock_client import MockDsmClient  # noqa: E402
from dsm_crypto.settings import Settings  # noqa: E402
from scripts.provision_dsm import ensure_keys  # noqa: E402

load_dotenv(Path(__file__).resolve().parent.parent / ".env")
tmp = Path(tempfile.mkdtemp())
backend = sys.argv[1] if len(sys.argv) > 1 else "mock"
dsm = MockDsmClient(tmp / "mock.json") if backend == "mock" else create_client(backend)
db = connect(tmp / "t.db")
print("backend:", dsm.backend_name)
print(ensure_keys(dsm))


def policy(**kw):
    base = dict(pattern="direct", key_name="kbtg-demo-aes128", mode="CBC", kek_name="kbtg-demo-kek",
                kek_mode="GCM", local_algorithm="AES-256-GCM", dek_max_records=100)
    base.update(kw)
    return Settings(**base)


def mix():
    out = {}
    for r in list_raw(db):
        d = describe(r["national_id"])
        k = f"{d['algorithm']} kid={d['kid'][:8]}"
        out[k] = out.get(k, 0) + 1
    return out


people = [mock_data.customer() for _ in range(6)]
enc = FieldEncryptor(dsm, policy())
ids = [add_customer(db, enc, p) for p in people[:3]]
print("baseline:", mix())

# A) CBC -> GCM  (config only)
enc = FieldEncryptor(dsm, policy(mode="GCM"))
ids.append(add_customer(db, enc, people[3]))
print("after CBC->GCM, before re-encrypt:", mix())
print(reencrypt_job.run(db, enc, table="customers", fields=SENSITIVE))
print("after re-encrypt:", mix())

# B) AES-128 -> AES-256
enc = FieldEncryptor(dsm, policy(mode="GCM", key_name="kbtg-demo-aes256"))
print(reencrypt_job.run(db, enc, table="customers", fields=SENSITIVE))
print("after 128->256:", mix())

# C) rotation (no config change)
dsm.rotate_key("kbtg-demo-aes256")
ids.append(add_customer(db, enc, people[4]))
print("after rotation, before re-encrypt:", mix())
print(reencrypt_job.run(db, enc, table="customers", fields=SENSITIVE))
print("after rotation re-encrypt:", mix())

# Envelope
n0 = dsm.call_count()
enc = FieldEncryptor(dsm, policy(pattern="envelope"))
print(reencrypt_job.run(db, enc, table="customers", fields=SENSITIVE))
ids.append(add_customer(db, enc, people[5]))
print("envelope:", mix(), "DSM calls:", dsm.call_count() - n0)

for cid, p in zip(ids, people):
    got = get_customer(db, FieldEncryptor(dsm, policy()), cid)
    assert (got["national_id"], got["account_no"], got["phone"]) == (p["national_id"], p["account_no"], p["phone"]), cid
print("ALL ROUND-TRIPS OK")
