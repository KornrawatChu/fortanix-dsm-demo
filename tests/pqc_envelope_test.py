"""
Scenario G end-to-end: envelope encryption moves from an RSA-wrapped DEK
(quantum-vulnerable) to an ML-KEM-encapsulated DEK (post-quantum) by changing
ONE config value (kek_name). Old RSA-wrapped records keep decrypting.

    python tests/pqc_envelope_test.py          # offline mock (ML-KEM simulated)
    python tests/pqc_envelope_test.py rest     # real DSM
    python tests/pqc_envelope_test.py sdk
"""
import json
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from dotenv import load_dotenv  # noqa: E402

from app import account_repository as repo  # noqa: E402
from scripts import reencrypt_job  # noqa: E402
from dsm_crypto.crypto_service import FieldEncryptor, describe  # noqa: E402
from dsm_crypto.dsm import create_client  # noqa: E402
from dsm_crypto.dsm.base import b64d  # noqa: E402
from dsm_crypto.dsm.mock_client import MockDsmClient  # noqa: E402
from app.mock_data import applicant  # noqa: E402
from dsm_crypto.settings import Settings  # noqa: E402
from scripts.provision_dsm import ensure_keys  # noqa: E402

load_dotenv(Path(__file__).resolve().parent.parent / ".env")
tmp = Path(tempfile.mkdtemp())
backend = sys.argv[1] if len(sys.argv) > 1 else "mock"
dsm = MockDsmClient(tmp / "mock.json") if backend == "mock" else create_client(backend)
db = repo.connect(tmp / "t.db")
ensure_keys(dsm)


def policy(kek):
    return Settings("envelope", "kbtg-demo-aes256", "GCM", kek, "GCM", "AES-256-GCM", 100, "OAEP_MGF1_SHA256")


def mix():
    out = {}
    for r in repo.list_applications(db):
        d = describe(r["national_id"])
        k = f"{d['algorithm']} kid={d['kid'][:8]}"
        out[k] = out.get(k, 0) + 1
    return out


people = [applicant() for _ in range(4)]
rsa = FieldEncryptor(dsm, policy("kbtg-demo-kek-rsa"))
refs = [repo.save_application(db, rsa, p) for p in people[:2]]
print(f"[{dsm.backend_name}] 1) RSA-wrapped DEKs :", mix())

n0 = dsm.call_count()
pq = FieldEncryptor(dsm, policy("kbtg-demo-mlkem"))          # config.yaml: kek_name changed, nothing else
refs += [repo.save_application(db, pq, p) for p in people[2:]]
print(f"    2) after kek_name -> ML-KEM ({dsm.call_count() - n0} DSM calls for 2 forms x 6 fields):", mix())

w = json.loads(repo.get_raw(db, refs[-1])["national_id"])["wdek"]
print(f"    ML-KEM ciphertext in the record: {len(b64d(w['ct']))} bytes (alg={w['alg']})")

reader = FieldEncryptor(dsm, policy("kbtg-demo-mlkem"))      # fresh instance: no DEK cache
for ref, p in zip(refs, people):
    got = repo.get_application(db, reader, ref)
    assert got["national_id"] == p["national_id"] and got["address"] == p["address"], ref
print("    3) RSA-wrapped + ML-KEM records all decrypt   : OK")

print("    4) re-encrypt:", reencrypt_job.run(db, pq, table=repo.TABLE, fields=repo.ENCRYPTED_FIELDS))
print("       after   :", mix())
print("PQC ENVELOPE SCENARIO OK")
