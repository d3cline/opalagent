"""Keep SDK resource managers; replace only unbounded HTTP and polling behavior."""
import time

import click
import opalstack
from opalstack.api import API_URL
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


class APIError(click.ClickException):
    def __init__(self, status, detail):
        self.status = status
        super().__init__(detail)


class Client(opalstack.Api):
    def __init__(self, token, timeout=30.0, wait_timeout=300.0):
        super().__init__(token=token)
        self.timeout = timeout
        self.wait_timeout = wait_timeout
        self.session = requests.Session()
        # Only GET is retried: replaying a create could duplicate infrastructure.
        retries = Retry(total=2, connect=2, read=2, status=2, backoff_factor=0.4,
                        status_forcelist=(429, 502, 503, 504), allowed_methods=frozenset({"GET"}),
                        respect_retry_after_header=False, raise_on_status=False)
        self.session.mount("https://", HTTPAdapter(max_retries=retries))

    def request(self, urlpath, method, dataObj, ensure_status=None):
        if ensure_status is None:
            ensure_status = [200]
        if method not in {"GET", "POST"}:
            raise click.ClickException("Unsupported SDK request method.")
        try:
            # POST uses a no-retry adapter to avoid even connection-level replay.
            if method == "POST":
                with requests.Session() as session:
                    resp = session.request(method, API_URL + urlpath, headers=self.api_headers,
                                           json=dataObj, timeout=self.timeout, allow_redirects=False)
            else:
                resp = self.session.request(method, API_URL + urlpath, headers=self.api_headers,
                                            timeout=self.timeout, allow_redirects=False)
        except requests.RequestException as exc:
            msg = "API connection failed or timed out."
            if method == "POST":
                msg += " The change may have reached Opalstack; inspect the resource before retrying."
            raise click.ClickException(msg) from exc
        try:
            result = resp.json()
        except ValueError:
            result = None
        if ensure_status and resp.status_code not in ensure_status:
            messages = {400: "API rejected the payload. Check field names, types and related resource IDs.",
                        401: "Authentication failed. Check your API token.",
                        403: "Your token does not permit this operation.",
                        404: "Resource or endpoint not found.",
                        429: "API rate limit reached. Try again later."}
            # Never echo response bodies: API validation errors can contain submitted secrets.
            msg = messages.get(resp.status_code, "Opalstack API request failed.")
            if method == "POST" and resp.status_code >= 500:
                msg += " Change outcome is uncertain; inspect state before retrying."
            raise APIError(resp.status_code, f"HTTP {resp.status_code}: {msg}")
        if result is None and resp.status_code == 200:
            raise click.ClickException("API returned an empty or invalid JSON response.")
        return resp, result

    def _wait(self, model, ids, deleted=False, delay=2.0, tries=0):
        deadline = time.monotonic() + self.wait_timeout
        pending = set(ids)
        count = 0
        while pending:
            if time.monotonic() >= deadline or (tries and count >= tries):
                raise click.ClickException(
                    "Provisioning wait expired. The change was submitted and may still finish; "
                    "inspect it before retrying."
                )
            for ident in list(pending):
                if time.monotonic() >= deadline:
                    break
                resp, data = self.request(f"/{model}/read/{ident}", "GET", None,
                                          ensure_status=[200, 404])
                if not deleted and resp.status_code == 404:
                    raise click.ClickException(
                        "Resource disappeared while waiting for provisioning. Inspect account state."
                    )
                if (deleted and resp.status_code == 404) or (
                    not deleted and isinstance(data, dict) and data.get("ready") is True
                ):
                    pending.remove(ident)
            count += 1
            if pending:
                time.sleep(min(delay, max(0, deadline - time.monotonic())))

    def wait_ready(self, model_name, uuids, delay=2.0, tries=0):
        self._wait(model_name, uuids, delay=delay, tries=tries)

    def wait_deleted(self, model_name, uuids, delay=2.0, tries=0):
        self._wait(model_name, uuids, deleted=True, delay=delay, tries=tries)
