"""
KBTG x Fortanix DSM - integration & crypto-agility demo.

    streamlit run app.py
"""
from __future__ import annotations

import dataclasses
import inspect
import os
import textwrap
import time
from datetime import datetime
from pathlib import Path

import pandas as pd
import requests
import streamlit as st
from dotenv import load_dotenv

import customer_repository as repo
import legacy_hardcoded
import mock_data
import reencrypt_job
import settings
from crypto_service import LOCAL_CIPHERS, FieldEncryptor, describe
from dsm import DsmError, create_client
from dsm.rest_client import RestDsmClient
from dsm.sdk_client import SdkDsmClient
from setup_dsm import DEMO_KEYS, ensure_keys

ROOT = Path(__file__).resolve().parent
load_dotenv(ROOT / ".env")
st.set_page_config(page_title="KBTG x Fortanix DSM Demo", page_icon="🔐", layout="wide")

BACKENDS = {"REST API (requests)": "rest", "Python SDK (sdkms)": "sdk", "Offline mock": "mock"}


# --------------------------------------------------------------------------- #
# Shared resources                                                            #
# --------------------------------------------------------------------------- #
@st.cache_resource
def get_dsm(backend: str):
    return create_client(backend)


@st.cache_resource
def get_db():
    return repo.connect()


def get_enc(dsm) -> FieldEncryptor:
    """One FieldEncryptor per (backend, policy) so the envelope DEK cache survives reruns."""
    s = settings.load()
    key = (dsm.backend_name, s)
    if st.session_state.get("enc_key") != key:
        st.session_state.enc = FieldEncryptor(dsm, s)
        st.session_state.enc_key = key
    return st.session_state.enc


def safe(fn, *a, **kw):
    try:
        return fn(*a, **kw)
    except DsmError as e:
        st.error(f"DSM error: {e}")
    except requests.RequestException as e:
        st.error(f"Network error reaching DSM: {e}")
    return None


def clean_source(fn) -> str:
    """Source for display: dedented, without the demo's call-inspector instrumentation."""
    out, depth = [], 0
    for line in textwrap.dedent(inspect.getsource(fn)).splitlines():
        s = line.strip()
        if depth or s.startswith(("self._record(", "started = time.perf_counter()")):
            depth += line.count("(") - line.count(")")
            continue
        out.append(line)
    return "\n".join(out)


def policy_mix(db) -> pd.DataFrame:
    rows = []
    for r in repo.list_raw(db):
        for f in repo.SENSITIVE:
            d = describe(r[f])
            rows.append({"Algorithm": d["algorithm"], "Key name": d["key_name"],
                         "Key version (kid)": d["kid"][:8] + "…"})
    if not rows:
        return pd.DataFrame(columns=["Algorithm", "Key name", "Key version (kid)", "Encrypted values"])
    df = pd.DataFrame(rows)
    return df.value_counts().rename("Encrypted values").reset_index()


def calls_since(dsm, n0: int) -> int:
    return dsm.call_count() - n0


# --------------------------------------------------------------------------- #
# Sidebar                                                                      #
# --------------------------------------------------------------------------- #
with st.sidebar:
    st.markdown("## 🔐 Fortanix DSM Demo")
    default = os.getenv("DSM_BACKEND", "rest")
    labels = list(BACKENDS)
    choice = st.radio("Integration method", labels,
                      index=list(BACKENDS.values()).index(default) if default in BACKENDS.values() else 0,
                      help="Same app, same business code - only the transport to DSM changes.")
    backend = BACKENDS[choice]
    if backend != "mock":
        st.caption(f"Endpoint: `{os.getenv('DSM_ENDPOINT', '(not set)')}`")
    else:
        st.warning("Offline mock - keys are simulated locally. Use only if DSM is unreachable.")

    dsm = safe(get_dsm, backend)
    if dsm is None:
        st.stop()
    db = get_db()
    enc = get_enc(dsm)

    if st.button("Connect & prepare demo keys", use_container_width=True):
        res = safe(ensure_keys, dsm)
        if res:
            st.session_state.keys_ready = res
    if st.session_state.get("keys_ready"):
        st.success("Connected to DSM")
        st.dataframe(pd.DataFrame(st.session_state.keys_ready, columns=["Key", "kid", "Status"]),
                     hide_index=True, use_container_width=True)

    s = enc.s
    st.markdown("### Current policy (`config.yaml`)")
    if s.pattern == "direct":
        st.code(f"pattern : direct\nkey     : {s.key_name}\nmode    : {s.mode}", language="yaml")
    else:
        st.code(f"pattern : envelope\nKEK     : {s.kek_name} ({s.kek_mode})\nlocal   : {s.local_algorithm}",
                language="yaml")

    with st.expander("Reset demo"):
        st.caption("Restores config.yaml to the baseline (AES-128 / CBC) and empties the customer table. "
                   "Keys in DSM are not deleted.")
        if st.button("Reset now", type="secondary"):
            settings.reset()
            repo.clear(db)
            st.session_state.pop("last_diff", None)
            st.rerun()


st.title("Fortanix DSM × Application Integration")
st.caption("A Python banking app that protects customer PII with keys held in Fortanix DSM (SaaS)")

tabs = st.tabs(["① Architecture", "② Customer data", "③ Integration point",
                "④ Direct vs Envelope", "⑤ Algorithm change lab", "⑥ Compliance & audit"])

# --------------------------------------------------------------------------- #
# ① Architecture                                                              #
# --------------------------------------------------------------------------- #
with tabs[0]:
    st.graphviz_chart("""
    digraph G {
      rankdir=LR; bgcolor="transparent"; node [shape=box style="rounded,filled" fontname="Helvetica" fontsize=11];
      user  [label="Teller / Channel app" fillcolor="#e8eefc"];
      subgraph cluster_app { label="Customer data centre / cloud (KBTG)"; style="rounded,dashed"; fontname="Helvetica";
        biz  [label="Business code\\ncustomer_repository.py\\n(no crypto knowledge)" fillcolor="#ffffff"];
        svc  [label="crypto_service.py\\nprotect() / reveal()\\nreads config.yaml" fillcolor="#fff4d6"];
        dsmc [label="dsm/ client\\n★ THE integration point\\nauth · encrypt · decrypt" fillcolor="#ffe0cc" penwidth=2];
        db   [label="Database\\n(ciphertext + kid only)" shape=cylinder fillcolor="#eeeeee"];
      }
      dsm [label="Fortanix DSM (SaaS)\\nFIPS 140-2 L3 HSM-backed\\nkeys never leave" fillcolor="#d8f0dd" penwidth=2];
      user -> biz; biz -> svc; svc -> dsmc; biz -> db [label=" SQL"];
      dsmc -> dsm [label=" HTTPS 443 (TLS)\\n REST / JSON\\n Bearer token" color="#d35400" fontcolor="#d35400" penwidth=2];
    }""", use_container_width=True)

    c = st.columns(4)
    c[0].markdown("#### 👩‍💻 Dev\n- 3 REST calls: **auth, encrypt, decrypt**\n- One module (`dsm/`) to own\n"
                  "- REST or official SDK - same API\n- Business code never touches keys or algorithms")
    c[1].markdown("#### 🛡️ Security\n- Keys generated & kept in DSM HSM, **non-exportable**\n"
                  "- App authenticates with an App API key → short-lived token\n"
                  "- Per-key policy: which app may encrypt / decrypt\n- Algorithm & key size centrally governed")
    c[2].markdown("#### 🖧 Infra\n- Outbound **HTTPS 443** only to `*.smartkey.io`\n"
                  "- Stateless app, no key files on servers\n- Rotation & migration without downtime\n"
                  "- Envelope pattern for high-volume / low-latency paths")
    c[3].markdown("#### 📋 Compliance\n- Every key use is **audit-logged** in DSM\n"
                  "- Key inventory: who / what / which version\n- Provable rotation & crypto policy\n"
                  "- Supports BOT IT risk / PDPA / PCI DSS key-management controls")

# --------------------------------------------------------------------------- #
# ② Customer data                                                             #
# --------------------------------------------------------------------------- #
with tabs[1]:
    left, right = st.columns([1, 2])
    with left:
        st.subheader("Onboard customers")
        n = st.number_input("Mock customers to add", 1, 50, 5)
        if st.button("➕ Add mock customers", type="primary"):
            n0 = dsm.call_count()
            t0 = time.perf_counter()
            for _ in range(n):
                if safe(repo.add_customer, db, enc, mock_data.customer()) is None:
                    break
            st.success(f"Added {n} customers · {calls_since(dsm, n0)} DSM calls · "
                       f"{(time.perf_counter() - t0) * 1000:.0f} ms")
        with st.form("manual"):
            st.markdown("**Or enter one manually**")
            m = mock_data.customer()
            f_name = st.text_input("Full name", m["full_name"])
            f_nid = st.text_input("National ID", m["national_id"])
            f_acct = st.text_input("Account no.", m["account_no"])
            f_phone = st.text_input("Phone", m["phone"])
            if st.form_submit_button("Save"):
                safe(repo.add_customer, db, enc, {"full_name": f_name, "national_id": f_nid,
                                                  "account_no": f_acct, "phone": f_phone, "branch": "Demo"})
    with right:
        st.subheader("What the database actually stores")
        st.caption("This is what a DBA, a backup tape or an attacker with SQL access sees.")
        raw = repo.list_raw(db)
        if raw:
            df = pd.DataFrame(raw)
            df["policy"] = [describe(v)["algorithm"] for v in df["national_id"]]
            for f in repo.SENSITIVE:
                df[f] = df[f].str.slice(0, 70) + "…"
            st.dataframe(df, hide_index=True, use_container_width=True, height=280)

            st.subheader("Authorised read (decrypt via DSM)")
            cid = st.selectbox("Customer id", [r["id"] for r in raw])
            if st.button("🔓 Decrypt this customer"):
                n0 = dsm.call_count()
                rec = safe(repo.get_customer, db, enc, cid)
                if rec:
                    st.json(rec)
                    st.caption(f"{calls_since(dsm, n0)} DSM call(s) - see the API inspector at the bottom")
            with st.expander("Stored JSON of one encrypted field (self-describing)"):
                st.code(raw[-1]["national_id"], language="json")
        else:
            st.info("No customers yet - add some on the left.")

# --------------------------------------------------------------------------- #
# ③ Integration point                                                         #
# --------------------------------------------------------------------------- #
with tabs[2]:
    st.subheader("Where the application connects to DSM")
    st.markdown("All DSM traffic goes through **one package: `dsm/`**. It exposes three operations. "
                "Everything else in the app calls `protect()` / `reveal()` and never sees a key.")
    layer = st.radio("Show layer", ["① DSM client (REST vs SDK)", "② crypto_service.py", "③ Business code",
                                    "④ curl equivalent"], horizontal=True)
    if layer.startswith("①"):
        op = st.radio("Operation", ["authenticate", "encrypt", "decrypt"], horizontal=True)
        a, b = st.columns(2)
        a.markdown("**REST - `dsm/rest_client.py`** (`requests`, works the same from any language)")
        a.code(clean_source(getattr(RestDsmClient, op)), language="python")
        b.markdown("**Official SDK - `dsm/sdk_client.py`** (`pip install sdkms`)")
        b.code(clean_source(getattr(SdkDsmClient, op)), language="python")
        st.caption("Call-inspector instrumentation lines are hidden here; see the files for the full code.")
    elif layer.startswith("②"):
        st.markdown("Reads the policy from `config.yaml` and stores metadata (kid, mode) with every value.")
        a, b = st.columns(2)
        a.code(inspect.getsource(FieldEncryptor.protect) + "\n" + inspect.getsource(FieldEncryptor.reveal),
               language="python")
        b.code(inspect.getsource(FieldEncryptor._direct), language="python")
    elif layer.startswith("③"):
        st.markdown("Business code - **no algorithm, no key, no DSM URL**. Unchanged in every scenario.")
        st.code(inspect.getsource(repo.add_customer) + "\n" + inspect.getsource(repo.get_customer),
                language="python")
    else:
        ep = os.getenv("DSM_ENDPOINT", "https://<region>.smartkey.io")
        st.code(f"""# 1) authenticate with the App API key -> bearer token
curl -s -X POST {ep}/sys/v1/session/auth -H "Authorization: Basic $DSM_API_KEY"

# 2) encrypt by key NAME (DSM picks the current key version)
curl -s -X POST {ep}/crypto/v1/encrypt -H "Authorization: Bearer $TOKEN" \\
  -d '{{"key":{{"name":"kbtg-demo-aes256"}},"alg":"AES","mode":"GCM","plain":"MS0xMjM0LTU2Nzg5LTAxLTI="}}'
# -> {{"kid":"…","cipher":"…","iv":"…","tag":"…"}}

# 3) decrypt by KID (the exact version stored with the data)
curl -s -X POST {ep}/crypto/v1/decrypt -H "Authorization: Bearer $TOKEN" \\
  -d '{{"key":{{"kid":"<kid>"}},"alg":"AES","mode":"GCM","cipher":"…","iv":"…","tag":"…"}}'""",
                language="bash")

# --------------------------------------------------------------------------- #
# ④ Direct vs Envelope                                                        #
# --------------------------------------------------------------------------- #
with tabs[3]:
    st.subheader("Two integration patterns, same business code")
    st.markdown("""
| | **Direct encryption** | **Envelope encryption** |
|---|---|---|
| Who encrypts data | DSM (inside HSM boundary) | Application, with a data key (DEK) |
| What DSM protects | The data itself | The DEK (wrapped by a KEK in DSM) |
| DSM calls | 1 per value | 1 per DEK (e.g. per 100 values) |
| Data leaves the app | Yes - plaintext sent to DSM over TLS | No - only the DEK is sent |
| Best for | PII fields, low/medium volume, strongest control | Bulk / high-TPS, large payloads, files |
| Changing algorithm | Config value (`mode`, key) only | Config if algorithm is in `LOCAL_CIPHERS`, otherwise app code |
""")
    n = st.slider("Records to encrypt and read back", 10, 200, 50, step=10)
    if st.button("▶ Run comparison", type="primary"):
        values = [mock_data.national_id() for _ in range(n)]
        out = []
        for pattern in ("direct", "envelope"):
            pol = dataclasses.replace(settings.load(), pattern=pattern)
            if pattern == "direct" and pol.mode not in ("CBC", "GCM"):
                pol = dataclasses.replace(pol, mode="GCM")
            n0, t0 = dsm.call_count(), time.perf_counter()
            e = FieldEncryptor(dsm, pol)
            stored = [safe(e.protect, v) for v in values]
            if None in stored:
                break
            enc_calls, enc_ms = calls_since(dsm, n0), (time.perf_counter() - t0) * 1000
            n1, t1 = dsm.call_count(), time.perf_counter()
            reader = FieldEncryptor(dsm, pol)          # cold cache, like a fresh service instance
            ok = all(reader.reveal(x) == v for x, v in zip(stored, values))
            out.append({"Pattern": pattern, "Encrypt: DSM calls": enc_calls, "Encrypt ms": round(enc_ms),
                        "Decrypt: DSM calls": calls_since(dsm, n1),
                        "Decrypt ms": round((time.perf_counter() - t1) * 1000),
                        "Bytes sent to DSM": (sum(len(v) for v in values) if pattern == "direct"
                                              else enc_calls * LOCAL_CIPHERS[pol.local_algorithm].key_bytes),
                        "What was sent": "customer data" if pattern == "direct" else "DEK only",
                        "Round-trip OK": ok})
        if out:
            res = pd.DataFrame(out)
            st.dataframe(res, hide_index=True, use_container_width=True)
            st.bar_chart(res.set_index("Pattern")[["Encrypt: DSM calls", "Decrypt: DSM calls"]], stack=False)
            st.caption("Latency includes the internet round-trip from this laptop to DSM SaaS.")

# --------------------------------------------------------------------------- #
# ⑤ Algorithm change lab                                                     #
# --------------------------------------------------------------------------- #
with tabs[4]:
    st.subheader("What has to change when the encryption algorithm changes?")
    top_l, top_r = st.columns([2, 3])
    with top_r:
        st.markdown("**Stored data by policy**")
        st.dataframe(policy_mix(db), hide_index=True, use_container_width=True)

    with top_l:
        scen = st.radio("Scenario", [
            "A · AES-CBC → AES-GCM",
            "B · AES-128 → AES-256",
            "C · Key rotation (same algorithm, new key version)",
            "D · Hard-coded vs config-driven",
            "E · Switch pattern / envelope local algorithm"])

    st.divider()

    def apply(**changes):
        st.session_state.last_diff = settings.update(**changes)
        st.rerun()

    if scen.startswith("A"):
        st.markdown("**Why:** CBC has no integrity protection (padding-oracle, bit-flipping). GCM is "
                    "authenticated encryption - tampering is detected on decrypt.\n\n"
                    "**DSM mechanism:** `mode` is a *parameter of the encrypt call*. Same key, no key change.")
        c1, c2 = st.columns(2)
        if c1.button("Apply: mode → GCM", type="primary", disabled=enc.s.mode == "GCM"):
            apply(mode="GCM")
        if c2.button("Roll back: mode → CBC", disabled=enc.s.mode == "CBC"):
            apply(mode="CBC")
    elif scen.startswith("B"):
        st.markdown("**Why:** new policy / regulation requires 256-bit keys.\n\n"
                    "**DSM mechanism:** key size is an *attribute of the Security Object*. "
                    "A new key `kbtg-demo-aes256` is created in DSM, the app just points to it.")
        c1, c2 = st.columns(2)
        if c1.button("Apply: key → kbtg-demo-aes256", type="primary", disabled=enc.s.key_name.endswith("256")):
            apply(key_name="kbtg-demo-aes256")
        if c2.button("Roll back: key → kbtg-demo-aes128", disabled=enc.s.key_name.endswith("128")):
            apply(key_name="kbtg-demo-aes128")
    elif scen.startswith("C"):
        target = enc.s.key_name if enc.s.pattern == "direct" else enc.s.kek_name
        st.markdown(f"**Why:** crypto-period ends / suspected compromise.\n\n"
                    f"**DSM mechanism:** *rekey* creates a new version under the **same name** `{target}`. "
                    "The app encrypts by name → picks up the new version automatically. "
                    "Old data still decrypts by its stored kid. **config.yaml: no change. Code: no change.**")
        if st.button(f"🔄 Rotate `{target}` in DSM", type="primary"):
            before = safe(dsm.get_key, target)
            after = safe(dsm.rotate_key, target)
            if before and after:
                st.session_state.last_diff = None
                st.success(f"Rotated: kid {before.kid[:8]}… → {after.kid[:8]}…")
                st.session_state.rotation_note = (before.kid, after.kid)
        if st.session_state.get("rotation_note"):
            o, nw = st.session_state.rotation_note
            st.info(f"Last rotation: `{o}` → `{nw}`. Add a customer to see new records use the new kid.")
    elif scen.startswith("D"):
        lines = inspect.getsource(legacy_hardcoded).splitlines()
        hits = [i for i, l in enumerate(lines) if "!ALGO" in l]
        a, b = st.columns(2)
        with a:
            st.error(f"**Hard-coded crypto: {len(hits)} lines in 4 places must change**  \n"
                     "+ big-bang migration (no version info) + key redeploy to every server")
            st.code(inspect.getsource(legacy_hardcoded), language="python", line_numbers=True)
        with b:
            st.success("**Config-driven with DSM: 1 line in `config.yaml`**  \n"
                       "+ online re-encryption job, old & new formats coexist")
            st.code(settings.diff(open(settings.BASELINE, encoding="utf-8").read(),
                                  open(settings.BASELINE, encoding="utf-8").read()
                                  .replace("mode: CBC", "mode: GCM")
                                  .replace("kbtg-demo-aes128", "kbtg-demo-aes256")), language="diff")
            st.markdown("| File | Hard-coded | With DSM |\n|---|---|---|\n"
                        "| onboarding service | change | – |\n| inquiry service | change | – |\n"
                        "| report job | change | – |\n| DB schema | change | – |\n"
                        "| key distribution | redeploy | – (in DSM) |\n| `config.yaml` | – | **1–2 lines** |")
    else:
        st.markdown("Envelope pattern: data is encrypted **in the app**, so the local algorithm lives in "
                    "`crypto_service.LOCAL_CIPHERS`. Choosing among registered algorithms is config; "
                    "adding a brand-new one (e.g. ChaCha20) is a code change in that **one** module.")
        c1, c2, c3 = st.columns(3)
        pat = c1.selectbox("pattern", ["direct", "envelope"], index=["direct", "envelope"].index(enc.s.pattern))
        alg = c2.selectbox("local_algorithm", list(LOCAL_CIPHERS), index=list(LOCAL_CIPHERS).index(enc.s.local_algorithm))
        c3.write("")
        if c3.button("Apply", type="primary"):
            apply(pattern=pat, local_algorithm=alg)

    if st.session_state.get("last_diff"):
        st.markdown("**The only change made: `config.yaml`**")
        st.code(st.session_state.last_diff, language="diff")

    st.divider()
    c1, c2 = st.columns(2)
    with c1:
        st.markdown("**Step 2 · New writes use the new policy immediately**")
        if st.button("➕ Add a customer now"):
            if safe(repo.add_customer, db, enc, mock_data.customer()):
                st.rerun()
    with c2:
        st.markdown("**Step 3 · Migrate old data online (re-encryption job)**")
        if st.button("♻ Run re-encryption job", type="primary"):
            bar = st.progress(0.0)
            n0 = dsm.call_count()
            stats = safe(reencrypt_job.run, db, enc, lambda i, t: bar.progress(i / t))
            if stats:
                stats["DSM calls"] = calls_since(dsm, n0)
                st.session_state.reenc = stats
                st.rerun()
        if st.session_state.get("reenc"):
            st.json(st.session_state.reenc)

# --------------------------------------------------------------------------- #
# ⑥ Compliance & audit                                                        #
# --------------------------------------------------------------------------- #
with tabs[5]:
    a, b = st.container(), st.container()
    with a:
        st.subheader("Key inventory")
        if st.button("Load key inventory"):
            used: dict[str, int] = {}
            for r in repo.list_raw(db):
                for f in repo.SENSITIVE:
                    k = describe(r[f])["kid"]
                    used[k] = used.get(k, 0) + 1
            kids = set(used)
            for name, *_ in DEMO_KEYS:
                k = safe(dsm.get_key, name)
                if k:
                    kids.add(k.kid)
            rows = []
            for kid in kids:
                k = safe(dsm.get_key_by_kid, kid)
                if k:
                    rows.append({"name": k.name, "kid": kid, "AES bits": k.key_size, "created": k.created_at,
                                 "state": k.state or ("enabled" if k.enabled else "disabled"),
                                 "values protected": used.get(kid, 0)})
            st.dataframe(pd.DataFrame(rows).sort_values(["name", "created"]), hide_index=True,
                         use_container_width=True)
    with b:
        st.subheader("DSM audit log")
        st.caption("Every authenticate / encrypt / decrypt / rotate is logged centrally by DSM.")
        if st.button("Load latest audit events"):
            logs = safe(dsm.audit_logs, 50)
            if logs is not None:
                df = pd.DataFrame(logs)
                keep = [c for c in ["time", "action_type", "actor_type", "severity", "message", "object_id"]
                        if c in df.columns]
                st.dataframe(df[keep] if keep else df, hide_index=True, use_container_width=True, height=420)
            else:
                st.info("If the app lacks permission to read audit logs, open DSM UI → **Audit Log** instead.")

# --------------------------------------------------------------------------- #
# API call inspector (always visible)                                         #
# --------------------------------------------------------------------------- #
st.divider()
with st.expander(f"🔎 DSM API call inspector - {dsm.backend_name} · {dsm.call_count()} calls this session",
                 expanded=True):
    calls = list(reversed(dsm.calls[-20:]))
    if calls:
        st.dataframe(pd.DataFrame([{"time": datetime.fromtimestamp(c.ts).strftime("%H:%M:%S"),
                                    "via": c.backend, "call": f"{c.method} {c.path}", "status": c.status,
                                    "ms": round(c.ms)} for c in calls]),
                     hide_index=True, use_container_width=True)
        i = st.selectbox("Inspect call", range(len(calls)),
                         format_func=lambda i: f"#{i + 1} {calls[i].method} {calls[i].path}")
        x, y = st.columns(2)
        x.markdown("**Request**")
        x.json(calls[i].request or {})
        y.markdown("**Response**")
        y.json(calls[i].response if isinstance(calls[i].response, (dict, list)) else {"body": str(calls[i].response)})
    else:
        st.caption("No calls yet.")
