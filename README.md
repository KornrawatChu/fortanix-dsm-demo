# KBTG × Fortanix DSM — Integration & Crypto-Agility Demo

**Horizon Bank** (fictional) — an ordinary online account-opening form. When the customer presses
*Submit*, PII is encrypted with keys held in **Fortanix DSM SaaS** before it is written to the database.

The customer sees a normal app. The integration is shown where developers really look:
**VS Code** (search `[DSM-INTEGRATION`) and a **live edit of `config.yaml`** while the app keeps running.

| What | Where |
|---|---|
| Customer site (form) | `http://localhost:5000` |
| Back office (decrypted view + raw DB values) | `http://localhost:5000/staff` |
| DSM audit log / keys | DSM UI (`https://apac.smartkey.io`) |
| Engineer console (deep-dive backup: benchmarks, key inventory) | `streamlit run console_app.py` |

## Project layout

| File | Role |
|---|---|
| `bank_app.py` + `templates/` + `static/` | Customer form + back office (Flask) |
| `account_repository.py` | Business code — calls `protect()` / `reveal()`, no crypto knowledge |
| `database.py` + `docker-compose.yml` | PostgreSQL (Docker) or SQLite — the DB only ever sees ciphertext |
| `show_db.py` | Prints what is stored (kid per record) straight from the DB |
| `seed_data.py` | Adds N fake applications (default 100) for the re-encryption scene |
| `crypto_service.py` | `[DSM-POLICY]` `protect()` / `reveal()` — direct & envelope, self-describing records |
| `config.yaml` | `[DSM-POLICY]` **The only file that changes** when the algorithm changes (auto-copied from `config.baseline.yaml`) |
| `dsm/rest_client.py` | `[DSM-INTEGRATION 1–3/3]` auth · encrypt · decrypt over REST |
| `dsm/sdk_client.py` | Same three integration points via the official SDK `sdkms` |
| `dsm/mock_client.py` | Offline DSM simulator (set `DSM_BACKEND=mock` in `.env`) |
| `reencrypt_job.py` | Online re-encryption to the current policy; commits per row, Ctrl+C is safe, re-run resumes |
| `legacy_hardcoded.py` | Anti-pattern for comparison (not executed) |
| `setup_dsm.py` | Creates demo keys in DSM (incl. `kbtg-demo-data-key`, RSA-2048) |
| `swap_key_type.py` | Changes the key type behind a name (RSA ↔ AES) |
| `console_app.py` | Streamlit engineer console (backup for deep-dive Q&A) |
| `tests/smoke_test.py` | End-to-end test of scenarios A–C + envelope |
| `tests/rsa_to_aes_test.py` | End-to-end test of scenario E (RSA → AES, same name) |

## 1. Prepare Fortanix DSM SaaS (one time, ~5 min)

1. Log in to your DSM region (e.g. `https://apac.smartkey.io`).
2. **Groups → Add group** → name `KBTG-Demo`.
3. **Apps → Add app** → name `kbtg-demo-app`, authentication **API Key**, assign to group `KBTG-Demo`
   (grant the group permission to create/manage keys).
4. Open the app → **View API key details** → copy the API key.
5. In this folder: copy `.env.example` to `.env`, set `DSM_ENDPOINT` (your region URL) and `DSM_API_KEY`.

> The API key is a secret. Keep it only in `.env` (git-ignored). Do not paste it in chat or slides.

## 2. Install & run (Windows / PowerShell)

The virtual environment lives **outside OneDrive** so thousands of package files are not synced.

```powershell
python -m venv $env:USERPROFILE\.venvs\kbtg-dsm-demo
& $env:USERPROFILE\.venvs\kbtg-dsm-demo\Scripts\python.exe -m pip install -r requirements.txt
& $env:USERPROFILE\.venvs\kbtg-dsm-demo\Scripts\python.exe setup_dsm.py
docker compose up -d          # PostgreSQL 16 on 127.0.0.1:5432 (needs Docker Desktop running)
& $env:USERPROFILE\.venvs\kbtg-dsm-demo\Scripts\python.exe bank_app.py
```

### Database
* **PostgreSQL in Docker** (`docker-compose.yml`, container `horizon-bank-db`, db `horizon_bank`, user `bank_app`,
  password = `PG_PASSWORD` in `.env`). Used when `DATABASE_URL` is set in `.env`.
* Without `DATABASE_URL` the app falls back to SQLite (`data\bank.db`).
* Wipe all demo data: `docker compose down -v` then `docker compose up -d`.

**Show the real database in DBeaver:** New Database Connection → **PostgreSQL** → Host `127.0.0.1`, Port `5432`,
Database `horizon_bank`, Username `bank_app`, Password = `PG_PASSWORD` from `.env` → Finish, then:
```sql
SELECT ref_no, first_name, last_name, national_id, mobile, monthly_income FROM account_applications;
```
Or without DBeaver: `docker exec -it horizon-bank-db psql -U bank_app -d horizon_bank`

Optional engineer console: `& $env:USERPROFILE\.venvs\kbtg-dsm-demo\Scripts\streamlit.exe run console_app.py`

**Reset between sessions:** stop the app, `docker compose down -v` + `docker compose up -d`, delete `config.yaml`
(it is recreated from the baseline).

`setup_dsm.py` creates three AES keys in DSM (non-exportable): `kbtg-demo-aes128`, `kbtg-demo-aes256`, `kbtg-demo-kek`.

Verify everything end-to-end before a customer session:

```powershell
& $env:USERPROFILE\.venvs\kbtg-dsm-demo\Scripts\python.exe tests\smoke_test.py rest
& $env:USERPROFILE\.venvs\kbtg-dsm-demo\Scripts\python.exe tests\smoke_test.py sdk
```

## 3. How it works

### The integration point (3 calls)
```
POST /sys/v1/session/auth   Authorization: Basic <API key>  -> bearer token
POST /crypto/v1/encrypt     {"key":{"name":...}, "alg":"AES", "mode":"GCM", "plain":...}
POST /crypto/v1/decrypt     {"key":{"kid":...},  "alg":"AES", "mode":"GCM", "cipher":..., "iv":..., "tag":...}
```
* Encrypt by **name** → DSM always uses the current key version (rotation needs no app change).
* Decrypt by **kid** → the exact version stored with the data.

### Self-describing ciphertext
Every encrypted column stores JSON like
`{"v":1,"p":"direct","key":"kbtg-demo-aes256","kid":"…","mode":"GCM","iv":"…","tag":"…","ct":"…"}`
so old and new formats coexist and re-encryption can run online, in batches, and be resumed.

### Algorithm-change scenarios
| Scenario | What changes | DSM mechanism |
|---|---|---|
| CBC → GCM | `config.yaml: mode` | Parameter of the encrypt call; same key |
| AES-128 → AES-256 | `config.yaml: key_name` | New Security Object with 256-bit size |
| Key rotation | nothing in the app | `POST /crypto/v1/keys/rekey` — new version, same name |
| RSA → AES, same key name | nothing in the app (it asks DSM for the key type, 10 s cache + auto-retry) | Rekey across types is refused, so: rename old key, create AES with the original name (`swap_key_type.py`) |
| Envelope local algorithm | `config.yaml: local_algorithm` (new algorithms: `crypto_service.LOCAL_CIPHERS`) | DSM wraps the DEK only |

## Troubleshooting
* **Smart App Control / "Application Control policy has blocked this file"** on first start: restart the
  app once; Windows checks new DLLs (pandas) on first load.
* **Audit log**: `GET /sys/v1/logs` returns `{"hits":[{"_source":{...}}]}`. The SDK's generated `LogsApi` model does
  not match this, so `sdk_client.py` uses the SDK's generic `call_api`. If an app gets 403, show **DSM UI → Audit Log**.
* **Rotated keys** keep their kid but are renamed `<name> (rotated at …)`; the new version takes the original name.
* **No internet at the venue**: set `DSM_BACKEND=mock` in `.env` and restart (simulated keys, same flow).
* **`bank.db` is locked** when deleting `data\`: another app (e.g. the Streamlit console) still has it open — stop it first.
* **`connection timeout` on start**: PostgreSQL is not running — start Docker Desktop, then `docker compose up -d`
  (or comment out `DATABASE_URL` in `.env` to use SQLite).
* **`OperationalError … connection abort`**: Postgres restarted while the app was running. `database.py` now
  reconnects automatically; if you still see it, restart `bank_app.py`.
* **psycopg "Application Control policy has blocked this file"**: Smart App Control checks the new DLL once; run again.
