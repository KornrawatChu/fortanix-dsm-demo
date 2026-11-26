"""
Horizon Bank (fictional) - online account opening.

A deliberately ordinary web app. The only thing special about it is that PII is
encrypted with keys held in Fortanix DSM before it is written to the database.

    python bank_app.py          ->  http://localhost:5000          (customer form)
                                    http://localhost:5000/staff    (back office)
"""
from __future__ import annotations

import json
import os
from pathlib import Path

from dotenv import load_dotenv
from flask import Flask, abort, redirect, render_template, request, url_for

import account_repository as repo
import mock_data
import settings
from crypto_service import FieldEncryptor, describe
from dsm import DsmError, create_client

ROOT = Path(__file__).resolve().parent
load_dotenv(ROOT / ".env")

app = Flask(__name__)
db = repo.connect()

# ════════════════════════════════════════════════════════════════════════════
# [DSM-INTEGRATION 0/3]  CONNECT
#   One Fortanix DSM client for the whole application.
#   Endpoint + App API key come from .env (or a vault) - never from code.
# ════════════════════════════════════════════════════════════════════════════
dsm = create_client()

_encryptors: dict = {}


def encryptor() -> FieldEncryptor:
    """
    [DSM-POLICY] Re-read config.yaml on EVERY request.
    Edit config.yaml and save -> the very next form submission uses the new
    algorithm/key. No restart, no redeploy, no code change.
    """
    s = settings.load()
    if s not in _encryptors:
        _encryptors.clear()
        _encryptors[s] = FieldEncryptor(dsm, s)
    return _encryptors[s]


# ---------------------------------------------------------------------------
# Customer-facing pages
# ---------------------------------------------------------------------------
sample_applicant = mock_data.applicant


@app.get("/")
def apply_form():
    return render_template("apply.html", sample=json.dumps(sample_applicant()))


@app.post("/apply")
def apply_submit():
    form = {k: request.form.get(k, "").strip() for k in
            ("title", "first_name", "last_name", "national_id", "date_of_birth", "mobile", "email",
             "address", "occupation", "monthly_income", "account_type")}
    missing = [k for k, v in form.items() if not v and k != "occupation"]
    if missing:
        return render_template("apply.html", sample=json.dumps(sample_applicant()), form=form,
                               error="Please complete all required fields."), 400
    try:
        ref_no = repo.save_application(db, encryptor(), form)
    except DsmError as e:
        return render_template("error.html", message=str(e)), 502
    return redirect(url_for("submitted", ref_no=ref_no))


@app.get("/submitted/<ref_no>")
def submitted(ref_no: str):
    raw = repo.get_raw(db, ref_no) or abort(404)
    return render_template("submitted.html", app=raw)


# ---------------------------------------------------------------------------
# Back office (bank staff)
# ---------------------------------------------------------------------------
@app.get("/staff")
def staff_list():
    rows = repo.list_applications(db)
    for r in rows:
        r["protection"] = describe(r["national_id"])
    return render_template("staff_list.html", rows=rows, policy=settings.load(),
                           backend=dsm.backend_name, endpoint=os.getenv("DSM_ENDPOINT", ""),
                           database=db.label)


@app.get("/staff/<ref_no>")
def staff_detail(ref_no: str):
    raw = repo.get_raw(db, ref_no) or abort(404)
    try:
        clear = repo.get_application(db, encryptor(), ref_no)
    except DsmError as e:
        return render_template("error.html", message=str(e)), 502
    stored = {f: json.dumps(json.loads(raw[f]), indent=2) for f in repo.ENCRYPTED_FIELDS}
    return render_template("staff_detail.html", app=clear, raw=raw, stored=stored,
                           fields=repo.ENCRYPTED_FIELDS, protection=describe(raw["national_id"]))


if __name__ == "__main__":
    print(f"\n  Horizon Bank demo  ->  http://localhost:5000   (back office: /staff)")
    print(f"  DSM: {dsm.backend_name} {os.getenv('DSM_ENDPOINT', '')}\n")
    app.run(host="127.0.0.1", port=5000, debug=True)
