#!/usr/bin/env python3
"""Assert both domains are still delegated to our Cloudflare zone, with no DS record.

The registrar is GoDaddy, not Cloudflare. A nameserver or DS change made there never
appears in the Cloudflare zone or in Cloudflare's audit log, so neither
dns_zone_inventory.py nor dns_audit_log.py can see it - yet it hands the whole domain
(web, mail, certificates) to whoever runs the new nameservers. This checks the
delegation from outside, over public DNS, with no key.

The nameservers are read from the REGISTRY (the .com / .ca servers), not from an
ordinary resolver. A resolver returns the NS list the domain's own servers publish, and
a hijacker's servers can publish ours, so that list alone would pass a hijack. The
registry's referral is what the registrar actually set. The resolver's list is checked
too, as a second opinion.

DNSSEC is deliberately off (docs/cutover/dns-cutover-runbook.md section 7.1), so any DS
record at all is an alarm: a DS that does not match Cloudflare's keys makes the domain
fail to resolve for every validating resolver. DS lives at the registry, so a resolver's
DS answer already comes from there.

Exit 0 = both domains exactly as expected. Exit 1 = drift. Exit 2 = cannot check.
"""

from __future__ import annotations

import json
import os
import socket
import struct
import sys
import urllib.request

DOH = "https://cloudflare-dns.com/dns-query?name={name}&type={rtype}"

# Measured 2026-11-03 over DNS-over-HTTPS, from the .com and .ca registry servers, and
# from the Cloudflare zone API (all report these two). Change only together with a
# deliberate, operator-approved move of the zone.
NAMESERVERS = {"donovan.ns.cloudflare.com.", "phoenix.ns.cloudflare.com."}
DOMAINS = ("wealthpreservationmanagement.com", "wealthpreservationmanagement.ca")

TYPE_CODE = {"A": 1, "NS": 2, "DS": 43}
REGISTRY_TRIES = 3  # registry servers asked before giving up (cannot check)


class CannotCheck(Exception):
    pass


def lookup(name: str, rtype: str) -> list[str]:
    req = urllib.request.Request(DOH.format(name=name, rtype=rtype),
                                 headers={"accept": "application/dns-json"})
    with urllib.request.urlopen(req, timeout=20) as resp:
        data = json.load(resp)
    status = data.get("Status")
    if status == 3:
        # NXDOMAIN on our own apex: the domain is gone from the registry. Drift, never
        # "no records": return a marker that matches nothing.
        return ["<NXDOMAIN>"]
    if status != 0:
        # SERVFAIL / REFUSED say the resolver could not answer, not that the domain moved.
        raise CannotCheck(f"resolver status {status} for {name} {rtype}")
    want = TYPE_CODE[rtype]
    # Only answers of the asked type; an answer without a type is kept, so it can
    # only alarm more.
    return [a.get("data", "").lower() for a in data.get("Answer", [])
            if a.get("type", want) == want]


# ---- the registry's own referral (plain DNS, no recursion) ----------------------------

def _query(name: str, qid: int) -> bytes:
    labels = b"".join(bytes([len(p)]) + p.encode("ascii") for p in name.rstrip(".").split("."))
    # flags 0: recursion NOT desired - we want the registry's referral, not an answer.
    return struct.pack(">HHHHHH", qid, 0, 1, 0, 0, 0) + labels + b"\x00" + struct.pack(">HH", 2, 1)


def _name(msg: bytes, pos: int) -> tuple[str, int]:
    """Read a (possibly compressed) name; returns (name with trailing dot, next pos)."""
    parts, end, jumps = [], None, 0
    while True:
        length = msg[pos]
        if length & 0xC0 == 0xC0:
            jumps += 1
            if jumps > 20:
                raise ValueError("compression loop")
            if end is None:
                end = pos + 2
            pos = ((length & 0x3F) << 8) | msg[pos + 1]
            continue
        if length == 0:
            return ".".join(parts).lower() + ".", end if end is not None else pos + 1
        parts.append(msg[pos + 1:pos + 1 + length].decode("ascii"))
        pos += 1 + length


def parse_referral(msg: bytes, qid: int, domain: str) -> set[str]:
    """NS names for `domain` in the answer or authority sections of a reply."""
    rid, flags, qd, an, ns, _ = struct.unpack(">HHHHHH", msg[:12])
    if rid != qid:
        raise ValueError("reply id does not match")
    if flags & 0x0200:
        raise ValueError("reply truncated")
    rcode = flags & 0x000F
    if rcode == 3:
        return {"<NXDOMAIN>"}
    if rcode != 0:
        raise ValueError(f"registry rcode {rcode}")
    pos = 12
    for _ in range(qd):
        _, pos = _name(msg, pos)
        pos += 4
    want = domain.rstrip(".").lower() + "."
    found = set()
    for _ in range(an + ns):
        owner, pos = _name(msg, pos)
        rtype, _, _, rdlen = struct.unpack(">HHIH", msg[pos:pos + 10])
        pos += 10
        if rtype == 2 and owner == want:
            found.add(_name(msg, pos)[0])
        pos += rdlen
    return found


def _udp(ip: str, payload: bytes) -> bytes:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.settimeout(5)
        s.sendto(payload, (ip, 53))
        return s.recvfrom(4096)[0]


def registry_ns(domain: str, send=_udp) -> set[str]:
    tld = domain.rsplit(".", 1)[1]
    servers = sorted(lookup(tld, "NS"))
    errors = []
    for server in servers[:REGISTRY_TRIES]:
        ips = [ip for ip in lookup(server, "A") if not ip.startswith("<")]
        if not ips:
            errors.append(f"{server}: no address")
            continue
        qid = int.from_bytes(os.urandom(2), "big")
        try:
            return parse_referral(send(ips[0], _query(domain, qid)), qid, domain)
        except (OSError, ValueError, IndexError, struct.error) as exc:
            errors.append(f"{server}: {type(exc).__name__}")
    raise CannotCheck(f"no .{tld} registry server answered ({'; '.join(errors) or 'none listed'})")


def _observe(fn, *args):
    """(value, None) or (None, why it could not be read)."""
    try:
        return fn(*args), None
    # Broad on purpose: a connection reset or a malformed reply on one observation must
    # not stop the others (URLError and JSONDecodeError are OSError and ValueError).
    except (CannotCheck, OSError, ValueError, KeyError, AttributeError, TypeError) as exc:
        return None, str(exc) if isinstance(exc, CannotCheck) else type(exc).__name__


def main() -> int:
    """Every observation is made and reported on its own, so one that cannot be read
    never hides a difference another one saw. Any difference wins over cannot-check."""
    drift, unseen = [], []
    for domain in DOMAINS:
        for where, fn, args in (("registry", registry_ns, (domain,)),
                                ("resolver", lookup, (domain, "NS"))):
            ns, why = _observe(fn, *args)
            if why:
                unseen.append(f"{domain} NS ({where}): {why}")
                print(f"CANNOT CHECK {domain} NS ({where}): {why}")
            elif set(ns) == NAMESERVERS:
                # Exact set: an extra nameserver beside ours is drift, since it answers
                # for the domain too. (An RRset holds no duplicates.)
                print(f"OK      {domain} NS ({where})")
            else:
                # The expected pair is printed too: the alarm tells the operator to compare
                # the registrar's nameservers against this line.
                drift.append(f"{domain} NS ({where}): expected {sorted(NAMESERVERS)}, found {sorted(ns)}")
                print(f"DRIFT   {domain} NS ({where}) -> {sorted(ns)}; expected {sorted(NAMESERVERS)}")
        ds, why = _observe(lookup, domain, "DS")
        if why:
            unseen.append(f"{domain} DS: {why}")
            print(f"CANNOT CHECK {domain} DS: {why}")
        elif ds == []:
            print(f"OK      {domain} no DS")
        else:
            drift.append(f"{domain} DS present: {ds}")
            print(f"DRIFT   {domain} DS present (DNSSEC is meant to be off) -> {ds}")
    if drift:
        print(f"\n{len(drift)} delegation difference(s). If nobody moved the domain at the"
              " registrar, treat it as a domain takeover in progress.")
        return 1
    if unseen:
        print(f"\n{len(unseen)} observation(s) could not be made. This is NOT an all-clear.")
        return 2
    print("\nBoth domains delegated to our Cloudflare nameservers at the registry, no DS.")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as exc:  # noqa: BLE001 - a crash must not borrow exit 1's meaning
        print(f"CANNOT CHECK: unexpected {type(exc).__name__}")
        sys.exit(2)
