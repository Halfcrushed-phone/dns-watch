#!/usr/bin/env python3
"""Report every change written to the firm's two Cloudflare zones, from Cloudflare's own log.

dns_zone_inventory.py compares one snapshot a day with a committed baseline. That has two
blind spots (RISK-2026-54): a record added and removed between two snapshots is never
seen (the shape of a certificate- or mail-capture attack), and anyone who can push the
baseline can make a change look expected. Cloudflare's account audit log records every
write as it happens and nobody here can edit it, so this reads that log instead.

Rules, each decided by the plan council (.council/dns-watch-blind-spots-plan-2026-11-03/):
- Deny by default. Every successful entry that is not a read ("view") and belongs to one
  of the two zones is reported, whatever product wrote it: DNS records, Worker routes,
  redirect rules, SSL settings. Account member invites and membership changes, and any
  write to an API token (account or user scope), are reported too: a new person or a new
  or widened token outlives any DNS change it was used for. So is any write in the user's
  own scope other than a sign-in (where Cloudflare logs email, password and two-factor
  changes is unmeasured: covered only if they land in that scope).
  Other account-level writes with no zone are NOT reported: the DNS edit key cannot make
  them. Measured 2026-11-04 over 2026-10-04..11-04 (1967 entries, 1639 of them views):
  of the 328 others, 12 were reported; the rest were Pages deploys (292), analytics
  queries logged as creates (8), account-settings copies of key writes (4, at the same
  minutes as the reported key lines), one Workers deploy (4 entries) and sign-ins (8
  user-record updates, all LOGIN or SSO_LOGIN); no load balancer, tunnel or
  custom-domain write was seen, so those are unreported and unmeasured (RISK-2026-54).
  There is no allowlist: an approved change is reported like any other, and the person
  who approved it confirms every printed line is theirs.
- Contiguous windows. Each run scans [A - LAG, start - LAG), where A is the start of the
  last run whose read succeeded. LAG covers the delay before an entry becomes readable.
  A failed read never moves the window on, so its stretch is scanned again next time.
  If no earlier successful read can be found, the scan starts at COMMISSIONED (the day
  the standing edit key was created): over-reporting is the safe side.
- External text (record content, token names) is printed with repr(), so a record whose
  content starts a line with "::" cannot inject a GitHub Actions command.
- AUDIT_PUBLIC_OUTPUT=1 (the phone-only watcher, whose run logs are public) prints record
  types and names only: no record content (an A record's content is an IP address) and
  no token names.

Exit 0 = the whole window was read and nothing was written. Exit 1 = the whole window
was read and changes are listed. Exit 2 = cannot see (no key, API error, the window
could not be determined) - never read exit 2 as all-clear. Anything found before a
failure is still printed.

Measuring (one-off, with the local key):  --since <ISO> --before <ISO> --shapes
prints how many entries of each kind the window holds, without their contents.
"""

from __future__ import annotations

import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path

API = "https://api.cloudflare.com/client/v4"
ACCOUNT_ID = "f3f7ed3a2768be6ae24f3f90982ee48a"  # the firm account (zone API, 2026-11-03)
ZONES = {"wealthpreservationmanagement.com", "wealthpreservationmanagement.ca"}
TOKEN_VAR = "CLOUDFLARE_AUDIT_READ_TOKEN"
LOCAL_TOKEN_FILE = Path.home() / ".wpm-cf-audit.env"
LAG = timedelta(hours=6)  # provisional until measured around a real change
COMMISSIONED = datetime(2026, 10, 28, tzinfo=timezone.utc)  # the edit key's first day
PAGE_LIMIT = 1000
MAX_PAGES = 50
# The phone-only watcher (sentinel/) runs a byte-identical copy of this file from its
# own workflow, so these two can be set from the environment there.
WORKFLOW_FILE = os.environ.get("AUDIT_WORKFLOW_FILE", "dmarc-dns-integrity.yml")
# Must equal the job's `name:` in .github/workflows/dmarc-dns-integrity.yml; a test
# reads the workflow and fails if they drift (the anchor would never be found, and
# every run would rescan from COMMISSIONED).
READ_JOB_NAME = os.environ.get("AUDIT_READ_JOB_NAME",
                               "the DNS change log could not be read - open this run")
RUN_PAGES = 3  # 90 runs back; past that, fall back to COMMISSIONED
PUBLIC = os.environ.get("AUDIT_PUBLIC_OUTPUT") == "1"


class CannotSee(Exception):
    pass


def iso(t: datetime) -> str:
    return t.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_time(text: str) -> datetime:
    return datetime.fromisoformat(text.replace("Z", "+00:00")).astimezone(timezone.utc)


def read_token() -> str:
    token = os.environ.get(TOKEN_VAR, "").strip()
    if not token and LOCAL_TOKEN_FILE.exists():
        for line in LOCAL_TOKEN_FILE.read_text().splitlines():
            if line.startswith(TOKEN_VAR + "="):
                token = line.split("=", 1)[1].strip()
    if not token:
        raise CannotSee(f"{TOKEN_VAR} is not set")
    return token


def http_json(url: str, headers: dict) -> dict:
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.load(resp)
    except urllib.error.HTTPError as exc:
        # Never echo the body or the query: either can carry request details.
        raise CannotSee(f"HTTP {exc.code} from {url.split('?')[0]}") from None
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
        raise CannotSee(f"unreachable: {type(exc).__name__} for {url.split('?')[0]}") from None


# ---- window ---------------------------------------------------------------------------

def last_successful_read(get=http_json) -> datetime | None:
    """Start time of the newest earlier run whose read job succeeded, or None."""
    repo = os.environ["GITHUB_REPOSITORY"]
    this_run = int(os.environ["GITHUB_RUN_ID"])
    headers = {"Authorization": f"Bearer {os.environ['GH_TOKEN']}",
               "Accept": "application/vnd.github+json"}
    base = f"https://api.github.com/repos/{repo}/actions"
    for page in range(1, RUN_PAGES + 1):
        # main only: a run on another branch must never move the window on.
        runs = get(f"{base}/workflows/{WORKFLOW_FILE}/runs?branch=main&per_page=30&page={page}",
                   headers).get("workflow_runs", [])
        for run in runs:  # newest first
            if run.get("id") == this_run:
                continue
            jobs = get(f"{base}/runs/{run['id']}/jobs?per_page=100", headers).get("jobs", [])
            for job in jobs:
                if job.get("name") == READ_JOB_NAME and job.get("conclusion") == "success":
                    return parse_time(job["started_at"])
        if len(runs) < 30:
            break
    return None


def window(anchor: datetime | None, start: datetime) -> tuple[datetime, datetime, bool]:
    """(since, before, fell_back). Contiguous with the last successful read; never
    earlier than COMMISSIONED, which is also where a missing anchor starts."""
    before = start - LAG
    if anchor is None:
        return COMMISSIONED, before, True
    return max(anchor - LAG, COMMISSIONED), before, False


# ---- reading the log -------------------------------------------------------------------

def fetch_entries(token: str, since: datetime, before: datetime, sink: list, get=http_json) -> None:
    """Append every entry in [since, before) to sink, following the cursor to the end.
    Raises CannotSee on any failure; sink keeps what was read before it."""
    headers = {"Authorization": f"Bearer {token}"}
    cursor = ""
    for _ in range(MAX_PAGES):
        q = {"since": iso(since), "before": iso(before), "limit": str(PAGE_LIMIT),
             "direction": "asc"}
        if cursor:
            q["cursor"] = cursor
        data = get(f"{API}/accounts/{ACCOUNT_ID}/logs/audit?{urllib.parse.urlencode(q)}", headers)
        if not data.get("success") or not isinstance(data.get("result"), list):
            raise CannotSee("audit log API reported failure or an unexpected shape")
        sink.extend(data["result"])
        cursor = (data.get("result_info") or {}).get("cursor") or ""
        if not cursor:
            return
    raise CannotSee(f"more than {MAX_PAGES * PAGE_LIMIT} entries in one window; not all read")


def _kind(res: dict) -> str:
    """The resource's product and type in one lowercase string, for word matching."""
    return f"{res.get('product')} {res.get('type')}".lower()


def _zone_name(entry: dict) -> str:
    return str((entry.get("zone") or {}).get("name") or "").lower().rstrip(".")


SIGN_INS = {"LOGIN", "SSO_LOGIN"}  # user-record writes a sign-in makes (measured 2026-11-04)


def reportable(entry: dict, since: datetime, before: datetime) -> bool:
    action = entry.get("action") or {}
    # A missing or unparseable time is kept: an entry we cannot place could be ours.
    try:
        t = parse_time(action["time"])
        if not since <= t < before:
            return False
    except (KeyError, TypeError, ValueError):
        pass
    if action.get("type") == "view":
        return False
    if action.get("result") == "failure":  # did not land
        return False
    res = entry.get("resource") or {}
    scope = res.get("scope")
    zone = _zone_name(entry)
    if zone in ZONES:
        return True
    if not zone and scope == "zones":  # a zone write we cannot attribute: assume ours
        return True
    if scope == "memberships":
        return True
    # Account members and keys, at any other scope: an invited person or a new key outlives
    # the DNS change. Measured 2026-11-04 over a month of the real log: an invite is
    # scope 'accounts' product 'members'; keys are product 'tokens' (account) or type
    # 'tokens' (user). Word matching, so a renamed label only alarms more.
    kind = _kind(res)
    if "token" in kind or "member" in kind:
        return True
    # The user's own scope, deny by default: a sign-in writes the user record (measured:
    # description LOGIN or SSO_LOGIN) and stays quiet; any other write there is reported.
    # Where Cloudflare logs email, password and two-factor changes is unmeasured; if they
    # land in this scope they are reported, if they land elsewhere they are not.
    if scope == "user":
        desc = action.get("description")
        return not (res.get("type") == "user" and isinstance(desc, str) and desc in SIGN_INS)
    return False


def _record(entry: dict) -> str:
    """Record fields a DNS write carries, if any (request or response body). In public
    mode, only for a DNS record: another resource's `name` can be a key's name."""
    res = entry.get("resource") or {}
    if PUBLIC and "dns" not in _kind(res):
        return "(details not shown in a public log)"
    for body in (res.get("response"), res.get("request")):
        if isinstance(body, dict):
            fields = ("type", "name") if PUBLIC else ("type", "name", "content")
            parts = [f"{k}={body[k]!r}" for k in fields
                     if isinstance(body.get(k), (str, int))]
            if parts:
                return " ".join(parts)
    return "(no record fields)"


def describe(entry: dict) -> str:
    action = entry.get("action") or {}
    res = entry.get("resource") or {}
    actor = entry.get("actor") or {}
    # Cloudflare's own label for the event (measured: "LOGIN", "Add Member", "Create DNS
    # Record"): tells a sign-in from an email change on a user-record line. Only letters,
    # digits, spaces and ()_- are printed - never an address or anything a log could act on.
    desc = str(action.get("description") or "")
    desc = desc if re.fullmatch(r"[A-Za-z][A-Za-z0-9 _()-]{0,60}", desc) else "?"
    return (f"CHANGE {action.get('time')!r} {action.get('type')!r} {desc!r} zone={_zone_name(entry) or '?'!r} "
            f"{res.get('product')!r}/{res.get('type')!r} {_record(entry)} "
            f"by {actor.get('type')!r}/{actor.get('context')!r}"
            + ("" if PUBLIC else f" token={actor.get('token_name')!r}"))


def shapes(entries: list) -> list[str]:
    c = Counter(((e.get("resource") or {}).get("scope"), (e.get("resource") or {}).get("product"),
                 (e.get("resource") or {}).get("type"), (e.get("action") or {}).get("type"),
                 _zone_name(e) or None) for e in entries)
    return [f"{n:5d}  scope={k[0]!r} product={k[1]!r} type={k[2]!r} action={k[3]!r} zone={k[4]!r}"
            for k, n in c.most_common()]


# ---- main ------------------------------------------------------------------------------

def _arg(argv: list, flag: str) -> str | None:
    return argv[argv.index(flag) + 1] if flag in argv else None


def main(argv: list[str], now: datetime | None = None) -> int:
    start = now or datetime.now(timezone.utc)
    entries: list = []
    try:
        since_arg, before_arg = _arg(argv, "--since"), _arg(argv, "--before")
        if since_arg:
            since = parse_time(since_arg)
            before = parse_time(before_arg) if before_arg else start - LAG
            fell_back = False
        elif "GITHUB_RUN_ID" in os.environ:
            since, before, fell_back = window(last_successful_read(), start)
        else:
            since, before, fell_back = window(None, start)
        print(f"Window {iso(since)} to {iso(before)}"
              + (" (no earlier successful read found: scanning from commissioning)" if fell_back else ""))
        if since >= before:
            print("Window is empty (runs are closer together than the lag allowance). Nothing to read yet.")
            return 0
        fetch_entries(read_token(), since, before, entries)
        failure = None
    except CannotSee as exc:
        failure = str(exc)
    except (KeyError, ValueError) as exc:
        failure = f"could not determine the window: {type(exc).__name__}"
        since = before = start
    found = [e for e in entries if reportable(e, since, before)]
    if "--shapes" in argv:  # measuring: counts only, never contents
        print("\n".join(shapes(entries)))
    else:
        for e in found:
            print(describe(e))
    if failure:
        print(f"CANNOT SEE: {failure}. This is NOT an all-clear"
              + (f"; {len(found)} change(s) were read before it failed (listed above)." if found else "."))
        return 2
    if found:
        print(f"\n{len(found)} change(s) to the zones in this window (of {len(entries)} log entries). "
              "Confirm every line is a change you approved; any other line means treat the "
              "DNS edit key as exposed.")
        return 1
    print(f"No changes to the zones in this window ({len(entries)} log entries read).")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv[1:]))
    except Exception as exc:  # noqa: BLE001 - a crash must not borrow exit 1's meaning
        print(f"CANNOT SEE: unexpected {type(exc).__name__}. This is NOT an all-clear.")
        sys.exit(2)
