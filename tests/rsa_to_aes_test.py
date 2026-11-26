"""
Scenario E end-to-end: the app keeps working while the key behind a NAME changes RSA -> AES.

    python tests/rsa_to_aes_test.py          # offline mock
    python tests/rsa_to_aes_test.py rest     # real DSM (swaps kbtg-demo-data-key, then swaps it back)
    python tests/rsa_to_aes_test.py sdk
"""
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from dotenv import load_dotenv  # noqa: E402

from app import account_repository as repo  # noqa: E402
from scripts import reencrypt_job  # noqa: E402
from app.mock_data import applicant as sample_applicant  # noqa: E402
from dsm_crypto.crypto_service import FieldEncryptor, describe  # noqa: E402
from dsm_crypto.dsm import create_client  # noqa: E402
from dsm_crypto.dsm.mock_client import MockDsmClient  # noqa: E402
from dsm_crypto.settings import Settings  # noqa: E402
from scripts.provision_dsm import ensure_keys  # noqa: E402
from scripts.swap_key_type import swap  # noqa: E402

load_dotenv(Path(__file__).resolve().parent.parent / ".env")
tmp = Path(tempfile.mkdtemp())
backend = sys.argv[1] if len(sys.argv) > 1 else "mock"
dsm = MockDsmClient(tmp / "mock.json") if backend == "mock" else create_client(backend)
db = repo.connect(tmp / "t.db")
ensure_keys(dsm)
NAME = "kbtg-demo-data-key"
if dsm.get_key(NAME).obj_type != "RSA":          # make sure we start from RSA
    swap(dsm, NAME, "RSA")

# The SAME policy object for the whole test: config.yaml never changes.
policy = Settings("direct", NAME, "GCM", "kbtg-demo-kek", "GCM", "AES-256-GCM", 100, "OAEP_MGF1_SHA256")
enc = FieldEncryptor(dsm, policy)                 # one long-lived app instance (with its type cache)


def mix():
    out = {}
    for r in repo.list_applications(db):
        d = describe(r["national_id"])
        k = f"{d['algorithm']} kid={d['kid'][:8]}"
        out[k] = out.get(k, 0) + 1
    return out


people = [sample_applicant() for _ in range(3)]
refs = [repo.save_application(db, enc, people[0])]
print(f"[{dsm.backend_name}] 1) app running on RSA          :", mix())

old, retired, new = swap(dsm, NAME, "AES")
print(f"    2) security team swaps key in DSM: {old.obj_type} {old.kid[:8]} -> {new.obj_type} {new.kid[:8]}")

refs.append(repo.save_application(db, enc, people[1]))   # cache still says RSA -> mismatch -> auto-retry
print("    3) next form submit (no restart, no config change):", mix())

for ref, p in zip(refs, people):
    got = repo.get_application(db, enc, ref)
    assert got["national_id"] == p["national_id"] and got["email"] == p["email"], ref
print("    4) old RSA record + new AES record both decrypt  : OK")

print("    5) re-encrypt:", reencrypt_job.run(db, enc, table=repo.TABLE, fields=repo.ENCRYPTED_FIELDS))
print("       after   :", mix())
got = repo.get_application(db, enc, refs[0])
assert got["national_id"] == people[0]["national_id"]

if backend != "mock":
    swap(dsm, NAME, "RSA")
    print("    (swapped the demo key back to RSA so the scene can be rehearsed again)")
print("RSA -> AES SCENARIO OK")
