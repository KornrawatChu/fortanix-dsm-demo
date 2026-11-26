"""
ANTI-PATTERN (reference only - not used by the demo app).

A typical "crypto inside the app" implementation: key in an env var / file,
algorithm and mode hard-coded wherever data is touched, and no metadata stored
with the ciphertext. Every line tagged  # !ALGO  must change to move from
AES-128-CBC to AES-256-GCM - across several modules, with a big-bang migration.
"""
import base64
import os

from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# --- key handling: key lives in the app, in plain sight -----------------------
SECRET_KEY = base64.b64decode(os.environ.get("APP_AES_KEY", base64.b64encode(b"0" * 16)))
assert len(SECRET_KEY) == 16, "AES-128 key expected"                       # !ALGO key size
BLOCK = 128                                                                 # !ALGO block/padding


# --- customer onboarding service ----------------------------------------------
def insert_customer(db, name, national_id, account_no):
    iv = os.urandom(16)                                                     # !ALGO IV size (GCM = 12)
    enc = Cipher(algorithms.AES(SECRET_KEY), modes.CBC(iv)).encryptor()     # !ALGO mode
    p = padding.PKCS7(BLOCK).padder()                                       # !ALGO padding (GCM: none)
    ct = enc.update(p.update(national_id.encode()) + p.finalize()) + enc.finalize()
    db.execute("INSERT INTO customers VALUES (?,?,?)",
               (name, base64.b64encode(iv + ct).decode(), account_no))     # !ALGO storage layout (no tag)


# --- customer inquiry service (separate team, copy-pasted) ---------------------
def get_national_id(db, customer_id):
    blob = base64.b64decode(db.execute("SELECT nid FROM customers WHERE id=?",
                                       (customer_id,)).fetchone()[0])
    iv, ct = blob[:16], blob[16:]                                           # !ALGO parse layout
    dec = Cipher(algorithms.AES(SECRET_KEY), modes.CBC(iv)).decryptor()     # !ALGO mode
    u = padding.PKCS7(BLOCK).unpadder()                                     # !ALGO padding
    return (u.update(dec.update(ct) + dec.finalize()) + u.finalize()).decode()


# --- nightly regulatory report job (yet another copy) ----------------------------
def export_report(db):
    for (blob,) in db.execute("SELECT nid FROM customers"):
        raw = base64.b64decode(blob)
        dec = Cipher(algorithms.AES(SECRET_KEY), modes.CBC(raw[:16])).decryptor()  # !ALGO mode + layout
        u = padding.PKCS7(BLOCK).unpadder()                                     # !ALGO padding
        yield (u.update(dec.update(raw[16:]) + dec.finalize()) + u.finalize()).decode()


# --- DB schema (migration script) -------------------------------------------------
SCHEMA = "CREATE TABLE customers (name TEXT, nid VARCHAR(64), acct TEXT)"  # !ALGO column width

# Problems beyond the !ALGO lines:
#  * No kid / version stored  -> cannot tell old vs new rows -> stop-the-world migration
#  * Key rotation = redeploy every service with the new key + re-encrypt everything at once
#  * Key is readable by anyone with access to the server / env / memory dump
#  * No central audit trail of who decrypted what
