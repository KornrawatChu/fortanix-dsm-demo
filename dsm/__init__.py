"""
Factory: pick the DSM backend from environment variables (.env).

    DSM_BACKEND   rest | sdk | mock
    DSM_ENDPOINT  https://<region>.smartkey.io
    DSM_API_KEY   App API key copied from DSM UI (Apps -> <app> -> API key)
    DSM_GROUP_ID  optional: group to create demo keys in
"""
from __future__ import annotations

import os
from pathlib import Path

from .base import DsmClient, DsmError, EncryptResult, KeyInfo  # noqa: F401

ROOT = Path(__file__).resolve().parent.parent


def create_client(backend: str | None = None) -> DsmClient:
    backend = (backend or os.getenv("DSM_BACKEND", "rest")).lower()
    if backend == "mock":
        from .mock_client import MockDsmClient
        return MockDsmClient(ROOT / "data" / "mock_dsm.json")

    endpoint = os.getenv("DSM_ENDPOINT", "").strip()
    api_key = os.getenv("DSM_API_KEY", "").strip()
    if not endpoint or not api_key:
        raise DsmError("DSM_ENDPOINT and DSM_API_KEY must be set in .env (or use backend 'mock').")
    group_id = os.getenv("DSM_GROUP_ID") or None
    verify = os.getenv("DSM_VERIFY_TLS", "true").lower() != "false"

    if backend == "sdk":
        from .sdk_client import SdkDsmClient
        return SdkDsmClient(endpoint, api_key, group_id, verify)
    from .rest_client import RestDsmClient
    return RestDsmClient(endpoint, api_key, group_id, verify)
