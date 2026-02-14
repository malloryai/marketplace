#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

DEFAULT_BASE_URL = "https://api.mallory.ai"


def _read_api_key(api_key_path: Path | None) -> str:
    env_key = os.getenv("MALLORY_API_KEY")
    if env_key:
        return env_key.strip()

    key_path = api_key_path or Path(__file__).resolve().parent / ".api_key"
    if not key_path.exists():
        raise FileNotFoundError(
            f"API key not found at {key_path}. Create it or set MALLORY_API_KEY."
        )

    key = key_path.read_text().strip()
    if not key:
        raise ValueError(f"API key file at {key_path} is empty.")

    return key


def _read_json_input(value: str | None, name: str) -> Any | None:
    if value is None:
        return None
    if value == "-":
        data = sys.stdin.read()
    elif value.startswith("@"):
        data = Path(value[1:]).read_text()
    else:
        data = value

    data = data.strip()
    if not data:
        return None
    try:
        return json.loads(data)
    except json.JSONDecodeError as exc:
        raise ValueError(f"{name} is not valid JSON.") from exc


def _read_stdin_if_available() -> str | None:
    if sys.stdin.isatty():
        return None
    data = sys.stdin.read().strip()
    return data or None


def _build_query(params: dict[str, Any] | None) -> str:
    if not params:
        return ""
    if not isinstance(params, dict):
        raise ValueError("Params JSON must be an object/dictionary.")
    return urlencode(params, doseq=True)


def _request(
    method: str,
    base_url: str,
    path: str,
    api_key: str,
    params: dict[str, Any] | None,
    body: Any | None,
) -> tuple[int, dict[str, str], bytes]:
    url = base_url.rstrip("/") + "/" + path.lstrip("/")
    query = _build_query(params)
    if query:
        url = f"{url}?{query}"

    headers = {
        "Authorization": f"Bearer {api_key}",
        "Accept": "application/json",
    }

    data = None
    if body is not None:
        data = json.dumps(body).encode("utf-8")
        headers["Content-Type"] = "application/json"

    req = Request(url, data=data, headers=headers, method=method.upper())
    with urlopen(req) as response:
        return response.status, dict(response.headers), response.read()


def _render_response(
    status: int, headers: dict[str, str], payload: bytes, raw: bool
) -> None:
    if raw:
        sys.stdout.write(payload.decode("utf-8", errors="replace"))
        return

    content_type = headers.get("Content-Type", "")
    text = payload.decode("utf-8", errors="replace")
    if "application/json" in content_type:
        try:
            parsed = json.loads(text)
        except json.JSONDecodeError:
            sys.stdout.write(text)
            return
        sys.stdout.write(json.dumps(parsed, indent=2, sort_keys=True))
    else:
        sys.stdout.write(text)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Mallory API CLI client (JSON-friendly).",
        epilog=(
            "Examples:\\n"
            "  python client.py get /v1/vulnerabilities --params '{\"limit\": 5}'\\n"
            "  echo '{\"filter\": \"type:ip.v4\"}' | python client.py get /v1/observables "
            "--params -\\n"
            "  echo '{\"urls\": [\"https://example.com\"]}' | "
            "python client.py post /v1/references --body -\\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("method", help="HTTP method (get, post, patch, delete)")
    parser.add_argument("path", help="API path (e.g., /v1/vulnerabilities)")
    parser.add_argument(
        "--params",
        help="JSON object for query params, use '-' for stdin or '@file.json'",
    )
    parser.add_argument(
        "--body",
        help="JSON body, use '-' for stdin or '@file.json'",
    )
    parser.add_argument(
        "--base-url",
        default=DEFAULT_BASE_URL,
        help=f"Base URL (default: {DEFAULT_BASE_URL})",
    )
    parser.add_argument(
        "--api-key-path",
        help="Path to .api_key (defaults to skills/mallory-api/.api_key)",
    )
    parser.add_argument(
        "--raw",
        action="store_true",
        help="Output raw response without JSON pretty print",
    )

    args = parser.parse_args()

    params = _read_json_input(args.params, "params")
    body = _read_json_input(args.body, "body")
    stdin_data = _read_stdin_if_available()
    if stdin_data and params is None and body is None:
        try:
            parsed_stdin = json.loads(stdin_data)
        except json.JSONDecodeError as exc:
            raise SystemExit(f"stdin is not valid JSON: {exc}") from exc
        if args.method.lower() in {"get", "delete"}:
            params = parsed_stdin
        else:
            body = parsed_stdin

    api_key_path = Path(args.api_key_path) if args.api_key_path else None
    api_key = _read_api_key(api_key_path)

    try:
        status, headers, payload = _request(
            args.method, args.base_url, args.path, api_key, params, body
        )
        _render_response(status, headers, payload, args.raw)
        return 0
    except HTTPError as exc:
        error_payload = exc.read().decode("utf-8", errors="replace")
        sys.stderr.write(f"HTTP {exc.code} {exc.reason}\\n{error_payload}\\n")
        return 1
    except URLError as exc:
        sys.stderr.write(f"Request failed: {exc}\\n")
        return 1
    except Exception as exc:  # noqa: BLE001 - CLI boundary
        sys.stderr.write(f"Error: {exc}\\n")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
