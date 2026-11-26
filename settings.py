"""Load / update config.yaml while keeping its comments (so diffs stay readable)."""
from __future__ import annotations

import difflib
import re
import shutil
from dataclasses import dataclass
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent
CONFIG = ROOT / "config.yaml"
BASELINE = ROOT / "config.baseline.yaml"


@dataclass(frozen=True)
class Settings:
    pattern: str
    key_name: str
    mode: str
    kek_name: str
    kek_mode: str
    local_algorithm: str
    dek_max_records: int
    rsa_mode: str = "OAEP_MGF1_SHA256"


def ensure_config() -> None:
    if not CONFIG.exists():
        shutil.copy(BASELINE, CONFIG)


def load() -> Settings:
    ensure_config()
    c = yaml.safe_load(CONFIG.read_text(encoding="utf-8"))
    e, env = c["encryption"], c["envelope"]
    return Settings(e["pattern"], e["key_name"], e["mode"], env["kek_name"], env["kek_mode"],
                    env["local_algorithm"], int(env["dek_max_records"]),
                    e.get("rsa_mode", "OAEP_MGF1_SHA256"))


def read_text() -> str:
    ensure_config()
    return CONFIG.read_text(encoding="utf-8")


def update(**changes) -> str:
    """Set top-level-unique keys (pattern, key_name, mode, ...) in place. Returns a unified diff."""
    old = read_text()
    new = old
    for key, value in changes.items():
        new, n = re.subn(rf"^(\s*{key}:\s*)([^\s#]+)", rf"\g<1>{value}", new, count=1, flags=re.M)
        if n == 0:
            raise KeyError(key)
    CONFIG.write_text(new, encoding="utf-8")
    return diff(old, new)


def diff(old: str, new: str) -> str:
    return "".join(difflib.unified_diff(old.splitlines(True), new.splitlines(True),
                                        "config.yaml (before)", "config.yaml (after)", n=1))


def reset() -> None:
    shutil.copy(BASELINE, CONFIG)
