"""Fetching headers over HTTP(S). Only used against targets the user is authorized to test."""
from __future__ import annotations

import urllib.request
from typing import Mapping


def fetch_headers(url: str, timeout: float = 10.0) -> Mapping[str, str]:
    if not url.startswith(("http://", "https://")):
        raise ValueError("URL must start with http:// or https://")
    request = urllib.request.Request(url, method="HEAD", headers={"User-Agent": "webheaders/0.1"})
    with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310
        return dict(response.headers.items())
