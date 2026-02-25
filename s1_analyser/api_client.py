"""
S1 API Client - Authenticated HTTP client for SentinelOne API v2.1.
Implements retry logic, rate-limit handling and pagination helpers.
"""
from __future__ import annotations

import logging
import time
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urljoin

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

logger = logging.getLogger(__name__)


class S1APIError(Exception):
    """Raised when the SentinelOne API returns an error."""

    def __init__(self, message: str, status_code: int = 0, body: str = ""):
        super().__init__(message)
        self.status_code = status_code
        self.body = body


class S1APIClient:
    """
    Thread-safe SentinelOne API client.

    Handles:
    - ApiToken authentication
    - Automatic retry on transient failures (5xx, network errors)
    - Rate-limit respect (HTTP 429 + Retry-After header)
    - Transparent cursor-based pagination
    - Optional verbose logging of every HTTP exchange
    """

    _TIMEOUT: int = 60          # seconds per request
    _RETRY_TOTAL: int = 2       # urllib3 retries for 5xx
    _PAGE_SIZE: int = 1000      # items per page

    def __init__(self, server_url: str, api_key: str, verbose: bool = False) -> None:
        self.base_url = server_url.rstrip("/")
        self._verbose = verbose

        retry_strategy = Retry(
            total=self._RETRY_TOTAL,
            backoff_factor=2.0,
            status_forcelist=[500, 502, 503, 504],
            allowed_methods=["GET", "POST"],
            raise_on_status=False,
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.session = requests.Session()
        self.session.mount("https://", adapter)
        self.session.mount("http://", adapter)
        self.session.headers.update({
            "Authorization": f"ApiToken {api_key}",
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": "S1-ThreatAnalyser/1.1.0",
        })

    # ------------------------------------------------------------------
    # Low-level request
    # ------------------------------------------------------------------

    def _request(
        self,
        method: str,
        endpoint: str,
        params: Optional[Dict] = None,
        json_body: Optional[Dict] = None,
    ) -> Dict:
        """Execute an HTTP request and return the parsed JSON response body."""
        url = urljoin(self.base_url + "/", endpoint.lstrip("/"))

        if self._verbose:
            param_str = f"  params={params}" if params else ""
            logger.info("→ %s %s%s", method, url, param_str)

        try:
            resp = self.session.request(
                method=method,
                url=url,
                params=params,
                json=json_body,
                timeout=self._TIMEOUT,
            )
        except requests.Timeout:
            raise S1APIError(f"Request timed out ({self._TIMEOUT}s) for {url}")
        except requests.ConnectionError as exc:
            raise S1APIError(f"Connection error reaching {url}: {exc}")

        if self._verbose:
            logger.info("← HTTP %d  (%d bytes)", resp.status_code, len(resp.content))

        # Rate limit
        if resp.status_code == 429:
            wait = int(resp.headers.get("Retry-After", 60))
            logger.warning("Rate-limited — sleeping %ds before retry", wait)
            time.sleep(wait)
            return self._request(method, endpoint, params, json_body)

        if resp.status_code == 401:
            raise S1APIError(
                "HTTP 401 — Authentication failed. Verify your API token.", 401
            )

        if resp.status_code == 403:
            raise S1APIError(
                f"HTTP 403 — Forbidden. Your token may lack the required permission "
                f"for: {endpoint}", 403
            )

        if resp.status_code == 404:
            raise S1APIError(
                f"HTTP 404 — Endpoint not found: {url}\n"
                "  Check the server URL and API version.", 404
            )

        if resp.status_code >= 400:
            body_preview = resp.text[:400] if resp.text else "(empty body)"
            raise S1APIError(
                f"HTTP {resp.status_code} from {url}\n  Body: {body_preview}",
                resp.status_code,
                resp.text,
            )

        if not resp.content:
            return {}

        try:
            return resp.json()
        except ValueError:
            raise S1APIError(
                f"Non-JSON response (HTTP {resp.status_code}) from {url}: "
                f"{resp.text[:200]}"
            )

    def get(self, endpoint: str, params: Optional[Dict] = None) -> Dict:
        return self._request("GET", endpoint, params=params)

    def post(self, endpoint: str, json_body: Dict) -> Dict:
        return self._request("POST", endpoint, json_body=json_body)

    # ------------------------------------------------------------------
    # Pagination
    # ------------------------------------------------------------------

    def get_all(
        self,
        endpoint: str,
        params: Optional[Dict] = None,
        progress_callback=None,
    ) -> List[Dict]:
        """
        Transparently fetch all pages from a cursor-paginated endpoint.

        progress_callback(fetched_so_far: int, total: int) is called after
        each page if provided.
        """
        params = dict(params or {})
        params["limit"] = self._PAGE_SIZE
        params.pop("cursor", None)

        all_items: List[Dict] = []

        while True:
            resp = self.get(endpoint, params)
            items = resp.get("data") or []
            all_items.extend(items)

            pagination = resp.get("pagination") or {}
            total = pagination.get("totalItems") or len(all_items)

            if progress_callback:
                progress_callback(len(all_items), total)

            next_cursor = pagination.get("nextCursor")
            if not next_cursor or not items:
                break

            params["cursor"] = next_cursor
            params.pop("skip", None)

        return all_items

    # ------------------------------------------------------------------
    # High-level wrappers
    # ------------------------------------------------------------------

    def verify_connection(self) -> Tuple[bool, str]:
        """
        Verify that the server is reachable and the token is valid.

        Returns (True, detail_string) on success, (False, error_message) on failure.

        Strategy: call GET /threats with countOnly=true (limit=1).
        This endpoint always exists and requires only 'Threats View' permission.
        """
        try:
            resp = self.get(
                "/web/api/v2.1/threats",
                params={"limit": 1, "countOnly": True},
            )
            total = resp.get("pagination", {}).get("totalItems", "?")
            return True, f"Token valid  ·  Total threats visible: {total}"
        except S1APIError as exc:
            return False, str(exc)
        except Exception as exc:
            return False, f"Unexpected error: {exc}"

    def get_threats_by_storyline(self, storyline: str) -> List[Dict]:
        """Return all threats whose storyline field contains *storyline*."""
        return self.get_all(
            "/web/api/v2.1/threats",
            params={"storyline__contains": storyline},
        )

    def get_threat_events(
        self,
        threat_id: str,
        progress_callback=None,
    ) -> List[Dict]:
        """
        Return all explore/events for a threat, sorted oldest-first (client-side).

        Note: sortby/sortorder are NOT supported on this endpoint — sorting is
        done client-side after all pages are collected.

        Requires 'Threat Forensics' or 'Endpoint Forensics View' permission.
        """
        events = self.get_all(
            f"/web/api/v2.1/threats/{threat_id}/explore/events",
            params={},
            progress_callback=progress_callback,
        )
        events.sort(key=lambda e: e.get("createdAt") or "")
        return events

    def get_threat_timeline(
        self,
        threat_id: str,
        progress_callback=None,
    ) -> List[Dict]:
        """Return the full activity timeline for a threat, sorted oldest-first (client-side)."""
        entries = self.get_all(
            f"/web/api/v2.1/threats/{threat_id}/timeline",
            params={},
            progress_callback=progress_callback,
        )
        entries.sort(key=lambda e: e.get("createdAt") or "")
        return entries
