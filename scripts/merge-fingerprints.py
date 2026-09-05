#!/usr/bin/env python3
"""Merge a labelled LANwatch fingerprint dump into the shared catalogue.

See docs/fingerprint-design.md section 12. The dump is private: its comment
lines carry MAC and IP addresses. This script strips every comment, and refuses
the whole file if an address survives into a data line.

Usage:
    scripts/merge-fingerprints.py <dump file> [catalogue file]
"""

import re
import sys
from pathlib import Path

FIELDS = 7
UNSET = "-"
DEFAULT_CATALOGUE = "lanwatch-fingerprints.txt"
GENERIC_OUI_THRESHOLD = 3
MAX_LINE = 8192

FNV_OFFSET = 0xCBF29CE484222325
FNV_PRIME = 0x100000001B3
MASK = (1 << 64) - 1

# Namespaces excluded from the core hash: vendors add and remove TXT keys and
# SSDP header names freely. Must match TokenNamespace::is_core in
# src/fingerprint.rs.
NON_CORE_PREFIXES = ("t:", "h:")
KNOWN_PREFIXES = ("m:", "t:", "s:", "h:", "d:", "v:", "u:", "e:", "x:")

MAC_RE = re.compile(r"\b(?:[0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}\b")
IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
IPV6_RE = re.compile(r"\b(?:[0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}\b")

# A DHCP option list is a run of numbers joined by "-", so "1-3-6-15-26-28-51"
# has the exact shape of a dash-separated MAC. It is built from the option
# codes alone and cannot carry an address, so it is the one thing the guard
# steps over. The pattern is deliberately strict: only digits and dashes, so a
# hand-edited "d:" token holding anything else is still checked.
DHCP_OPTION_RE = re.compile(r"^d:\d+=[\d-]+$")

HEADER = """\
# LANwatch fingerprint profile catalogue.
#
# Tab separated, seven fields:
#   core_hash  device_type  vendor  label  flags  tokens  meta
#
# `-` means "not set". `flags` carries `generic` for a copied default profile.
# `meta` holds n=<units seen> and oui=<distinct OUI vendors>.
#
# Built with scripts/merge-fingerprints.py. See docs/fingerprint-design.md.
"""


def fnv1a64(data: bytes) -> int:
    """FNV-1a, 64 bit. Must match fnv1a64 in src/fingerprint.rs."""
    value = FNV_OFFSET
    for byte in data:
        value ^= byte
        value = (value * FNV_PRIME) & MASK
    return value


def core_hash(tokens):
    core = [t for t in tokens if not t.startswith(NON_CORE_PREFIXES)]
    return fnv1a64("\n".join(core).encode("ascii", "ignore"))


def parse_meta(field):
    observations, oui = 1, 1
    for part in field.split(","):
        key, _, value = part.strip().partition("=")
        if not value.strip().isdigit():
            continue
        if key.strip() == "n":
            observations = int(value)
        elif key.strip() == "oui":
            oui = int(value)
    return observations, oui


def address_in_row(fields):
    """Returns the first part of a row that looks like an address, else None.

    Checks part by part rather than whole lines, so one token that is exempt
    cannot hide an address sitting next to it.
    """
    for field in fields:
        for part in field.split(","):
            part = part.strip()
            if DHCP_OPTION_RE.match(part):
                continue
            if MAC_RE.search(part) or IPV4_RE.search(part) or IPV6_RE.search(part):
                return part
    return None


def read_rows(path, *, guard_addresses):
    """Yields (fields, line_number) for every data line in a file."""
    rows = []
    for number, raw in enumerate(Path(path).read_text().splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith("#") or line.startswith("//"):
            continue
        if len(line) > MAX_LINE:
            print(f"{path}:{number}: skipped, longer than {MAX_LINE} bytes")
            continue
        fields = [f.strip() for f in line.split("\t")]
        if guard_addresses:
            found = address_in_row(fields)
            if found:
                sys.exit(
                    f"{path}:{number}: a data line contains a MAC or IP address.\n"
                    f"  {found}\n"
                    "Refusing the whole file. Addresses belong in comments only, and "
                    "comments never reach the catalogue."
                )
        if len(fields) != FIELDS:
            print(f"{path}:{number}: skipped, {len(fields)} fields, expected {FIELDS}")
            continue
        rows.append((fields, number, path))
    return rows


def main():
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    dump = sys.argv[1]
    catalogue = sys.argv[2] if len(sys.argv) > 2 else DEFAULT_CATALOGUE

    profiles = {}
    for fields, _, _ in read_rows(catalogue, guard_addresses=False) if Path(catalogue).exists() else []:
        profiles[fields[0]] = fields

    added = merged = skipped = 0
    for fields, number, path in read_rows(dump, guard_addresses=True):
        stored, device_type, vendor, label, flags, tokens, meta = fields

        if label == UNSET or not label:
            print(f"{path}:{number}: skipped, still unlabelled")
            skipped += 1
            continue

        token_list = sorted({t for t in (t.strip() for t in tokens.split(",")) if t})
        token_list = [t for t in token_list if t.startswith(KNOWN_PREFIXES)]
        if not token_list:
            print(f"{path}:{number}: skipped, no usable token")
            skipped += 1
            continue

        # The hash is derived from the tokens, so it is recomputable. A line
        # whose stored hash disagrees with its own tokens is rejected: one of
        # the two is wrong and there is no way to tell which.
        computed = f"{core_hash(token_list):016x}"
        if stored.lower() != computed:
            print(f"{path}:{number}: skipped, hash {stored} does not match its tokens ({computed})")
            skipped += 1
            continue

        observations, oui = parse_meta(meta)
        existing = profiles.get(computed)
        if existing:
            old_n, old_oui = parse_meta(existing[6])
            observations += old_n
            oui = max(oui, old_oui)
            # The better attested label wins; a tie keeps what is already there.
            if old_n >= observations - old_n:
                device_type, vendor, label = existing[1], existing[2], existing[3]
            merged += 1
        else:
            added += 1

        # Three unrelated OUI vendors cannot be one product, so the profile is a
        # copied default whatever the flags field claims.
        flag_set = {f.strip() for f in flags.split(",") if f.strip() and f.strip() != UNSET}
        if oui >= GENERIC_OUI_THRESHOLD:
            flag_set.add("generic")
        flags = ",".join(sorted(flag_set)) or UNSET

        profiles[computed] = [
            computed,
            device_type,
            vendor,
            label,
            flags,
            ",".join(token_list),
            f"n={observations},oui={oui}",
        ]

    # Sorted by hash so a diff stays readable and two contributors do not fight
    # over line order.
    out = [HEADER]
    for key in sorted(profiles):
        out.append("\t".join(profiles[key]) + "\n")
    Path(catalogue).write_text("".join(out))

    print(f"{catalogue}: {len(profiles)} profile(s) ({added} added, {merged} merged, {skipped} skipped)")


if __name__ == "__main__":
    main()
