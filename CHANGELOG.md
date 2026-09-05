# Changelog

All notable changes to LANwatch are recorded here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and the project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Entries before v0.11.0 are summarised from the commit history; only the releases
that changed behaviour are listed.

## [Unreleased]

### Added

- **Device attribute fingerprinting.** LANwatch now identifies a device by the
  *set of attributes it advertises*, not by the name it sends. Attributes are
  collected from mDNS service types and TXT keys, SSDP targets and header names,
  and DHCPv4/DHCPv6 option lists and vendor classes. Values are discarded and
  only keys are kept, so firmware versions, serial numbers and user-chosen names
  never enter a fingerprint. See `docs/fingerprint-design.md`.
  - Two hashes per device: a `core` hash that survives a firmware update, and a
    tighter `full` hash. Format: `lwfp1:<core>:<full>:<token count>`.
  - A device is only usable once it is **ripe**: at least 4 tokens, at least
    120 seconds old, and quiet for 60 seconds. A half-collected set never
    reaches a shared catalogue.
  - Fuzzy matching by Jaccard similarity over core tokens, gated behind a rare
    token so a device sharing only common tokens gets no match.
  - A profile seen under three or more unrelated OUI vendors is flagged
    `generic` automatically: it loses 25 confidence points and never sets a
    device type. This is what stops "everything looks like a Chromecast".
  - Confidence is capped at 99. A fingerprint is evidence, not proof.
- **Reviewing devices in the dashboard.** The device modal has an *Identify this
  device* panel: a device-type picker, a vendor field and a product-name field.
  Corrections are stored in a new `device_overrides` table, so unlike an
  `--override` file entry they survive a restart. Reviewed devices are marked
  with a check in the list.
- **`GET /fingerprints/export`** and an *Export Fingerprints* button, which build
  the shared catalogue from every reviewed and ripe device. The result carries
  no MAC, IP or hostname, so it is safe to share. This replaces hand-editing a
  dump for the normal workflow.
- **New API routes:** `PUT` and `DELETE /devices/{mac}/classification`,
  `GET /device-types`, `GET /fingerprints/export`.
- **`--api-readonly`** refuses every state-changing route with 403 while leaving
  reads working. The API has no authentication, so this matters whenever the
  listener is reachable beyond a trusted network.
- **`--fingerprints <FILE>`** loads a fingerprint catalogue at startup.
- **`--dump-fingerprints <FILE>`** writes a private labelling worksheet from the
  database and exits. Needs no interface and no root. The `device_type` and
  `vendor` fields arrive pre-filled with LANwatch's own guess, so the task is
  review rather than transcription.
- **`--forget <MAC>`** erases one device completely: its sightings, its
  attribute tokens and any correction. It is a CLI command rather than a button
  so that no single click can destroy labelling that cannot be recovered.
- **`scripts/merge-fingerprints.py`** and `make fingerprints-merge` fold a
  reviewed export into `lanwatch-fingerprints.txt`. The script refuses the whole
  file if a data line contains anything shaped like a MAC or an IP address.
- **`scripts/check-dashboard.js`** and `make check-dashboard` verify that every
  function the bundled dashboard calls actually exists, including from inline
  `onclick` handlers. The dashboard is one inline script with no build step, so
  a typo in a function name was previously only found by clicking the button
  that called it. Now runs in CI.
- **`examples/api_smoke.rs`** starts the real API server over a real database,
  for driving the endpoints by hand.
- **An export tally.** The export file carries a
  `# summary devices=.. reviewed=.. ripe=.. exported=..` line, and the dashboard
  reads it back so an empty export says which of the two conditions was not met
  rather than restating the rule.

### Changed

- Removing a device, resetting a device and forgetting a device are now three
  distinct actions. Discovery is keyed on MAC alone, so a device still on the
  LAN reappears within seconds of a removal; keeping the correction means one
  careless click cannot destroy review work.

  | Action | Clears | Keeps |
  |---|---|---|
  | Remove Device | the `devices` row | the correction and the tokens |
  | Reset to guess | the correction | the sighting and the tokens |
  | `--forget <MAC>` | all three | nothing |

- `DeviceInfo` gained `fingerprint`, `fingerprint_label`,
  `fingerprint_confidence` and `product_label`, all exposed in the JSON API.
  The CSV export keeps its existing field order and semantics: the new fields
  are carried by the database and the JSON API only, so no migration is needed.
- The `devices` table gained the three fingerprint columns, and two tables were
  added (`device_attributes`, `device_overrides`). All are created on an
  existing database automatically at startup. No migration step and no database
  wipe is needed.

### Fixed

- **Attribute tokens were never written to the database.** The capture loop
  flushed only when a *device field* changed. On a settled network every mDNS
  and SSDP announcement is a repeat, so the counter stayed at zero, no flush
  happened, and the collected tokens sat in memory until the process exited.
  The loop now asks the tracker what is waiting (`has_pending_writes`) instead
  of inferring it from a count of changed devices.
- **A rediscovered device briefly wore its old guess.** After a removal, a
  correction was only re-applied by the capture loop's next sweep. It is now
  applied the moment the device is seen again.
- **A device with a randomised MAC was named "Private Device".** The dashboard
  had the same fallback copy-pasted in three places, each discarding
  `device_type` when the vendor was `Private MAC Address`. A randomised MAC
  names no manufacturer, so that string describes the address, not the device.
  All three call sites now share one `deviceDisplayName` function that falls
  back to the device type, giving `Android Phone (85:FD:E7)`.
- **Saving a correction reported "Could not save" even when it succeeded.** The
  dashboard called a function that did not exist, and the `try` block wrapped
  both the request and the redraw, so a rendering error was reported as a failed
  save. The two are now separate, and a real failure reports the server's own
  message or the HTTP status.
- **The merge script refused every file containing a DHCP option list.** The
  option-55 token joins its codes with `-`, so `15-26-28-51-58-59` matched the
  dash-separated MAC pattern and tripped the privacy guard. The guard now checks
  token by token and steps over exactly one thing: a `d:<option>=<digits and
  dashes>` token.
- **A DHCP option list broke the catalogue on reload.** The option-55 token
  originally joined its codes with `,`, which is the catalogue's own token
  separator, so one token split into six. Option lists now join with `-`,
  `normalize_ascii` folds whitespace and commas to `-`, and `build_token`
  refuses any value containing a comma.

## [0.15.0]

### Changed

- Removed the mDNS and SSDP view types and their duplicated API surface.

### Fixed

- Device mis-attribution from reflected, aggregate and MAC-shaped packets.

## [0.14.0]

### Fixed

- Parser denial of service, inventory spoofing, and auto-saves that were never
  persisted.

## [0.13.0]

### Fixed

- Pagination overflow, OUI file misparsing, and IP-index corruption.

## [0.12.0]

### Added

- Remove a single device and flush all devices, from the dashboard and the API.
- LANwatch logo and release version in the dashboard.

## [0.11.0]

### Added

- Manual per-device classification overrides (`--override`, `--overrides`).

### Changed

- Refactor: `Vendor` and `DeviceType` enums, zero-copy MACs, and sniffer/tracker
  hot-path cleanup.

### Fixed

- Stored XSS and CSV injection from untrusted device data.

## [0.10.3]

### Changed

- Table-driven matching for the mDNS and SSDP heuristics.
- Feature-gated `MODEL_RULES` to prevent `dead_code` warnings.

[Unreleased]: https://github.com/rvido/lanwatch/compare/v0.15.0...HEAD
[0.15.0]: https://github.com/rvido/lanwatch/compare/v0.14.0...v0.15.0
[0.14.0]: https://github.com/rvido/lanwatch/compare/v0.13.0...v0.14.0
[0.13.0]: https://github.com/rvido/lanwatch/compare/v0.12.2...v0.13.0
[0.12.0]: https://github.com/rvido/lanwatch/compare/v0.11.1...v0.12.0
[0.11.0]: https://github.com/rvido/lanwatch/compare/v0.10.3...v0.11.0
[0.10.3]: https://github.com/rvido/lanwatch/compare/v0.10.2...v0.10.3
