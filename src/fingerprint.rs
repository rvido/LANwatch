//! Device attribute fingerprinting.
//!
//! Identifies a device from the *set of attributes it advertises* rather than
//! from a name it happens to send. See `docs/fingerprint-design.md` for the
//! rules this module implements; the section numbers in the comments below
//! refer to that document.
//!
//! This module is unconditional. DHCP fingerprinting must work in the minimal
//! `--no-default-features` build, so only the mDNS and SSDP collectors are
//! feature gated.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fmt;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;
use std::time::{Duration, SystemTime};

use crate::types::{DeviceType, Vendor};

#[cfg(feature = "mdns")]
use crate::parser::mdns::{MdnsRecord, MdnsRecordData, MdnsRecordType};
#[cfg(feature = "ssdp")]
use crate::parser::ssdp::SsdpPacket;
use crate::types::{Dhcpv4Packet, Dhcpv6Option};

/// Format version carried by every stored fingerprint string.
///
/// Bumping this invalidates both the stored hashes and the stored tokens,
/// because a change to the normalisation rules makes old tokens wrong too.
pub const FINGERPRINT_VERSION: &str = "lwfp1";

/// Longest accepted token, prefix included.
///
/// An over-long token is dropped, never truncated: truncation would map two
/// different attributes onto one token.
pub const MAX_TOKEN_LEN: usize = 128;

/// Most tokens kept for one device.
pub const MAX_TOKENS_PER_DEVICE: usize = 256;

/// Longest accepted catalogue line.
pub const MAX_CATALOGUE_LINE: usize = 8192;

/// Age, in days, after which a token that stopped being advertised is pruned.
pub const TOKEN_STALE_DAYS: i64 = 30;

/// Fewest tokens a device needs before a non-exact match is allowed.
pub const MIN_TOKENS_FOR_MATCH: usize = 4;

/// Age a device needs before a non-exact match is allowed.
pub const FINGERPRINT_MIN_AGE_SECS: u64 = 120;

/// Quiet time, with no new token, before a non-exact match is allowed.
pub const FINGERPRINT_QUIET_SECS: u64 = 60;

/// A token is "rare" when it appears in at most this share of the catalogue.
pub const RARE_TOKEN_MAX_SHARE: f32 = 0.05;

/// Distinct OUI vendors that mark a profile as a copied default.
pub const GENERIC_OUI_THRESHOLD: u32 = 3;

/// Number of tab separated fields in a catalogue line.
const CATALOGUE_FIELDS: usize = 7;

/// Field value meaning "not set".
const UNSET: &str = "-";

/// The namespace a token belongs to.
///
/// The prefix is part of the token, so the namespace is recoverable from a
/// stored string without a schema change.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum TokenNamespace {
    /// mDNS service type, e.g. `m:_googlecast._tcp`.
    MdnsService,
    /// mDNS TXT key scoped to its service, e.g. `t:_googlecast._tcp/md`.
    MdnsTxtKey,
    /// SSDP `ST`/`NT` search target, e.g. `s:urn:schemas-upnp-org:device:...`.
    SsdpTarget,
    /// SSDP header name, e.g. `h:server`.
    SsdpHeader,
    /// DHCPv4 option 55 parameter request list, order preserved.
    DhcpOptionList,
    /// DHCPv4 option 60 / DHCPv6 option 16 vendor class.
    VendorClass,
    /// DHCPv6 option 15 user class.
    UserClass,
    /// DHCPv6 option 16 IANA enterprise number.
    Enterprise,
    /// Presence flag, e.g. `x:opt43`.
    Flag,
}

impl TokenNamespace {
    /// The literal prefix written into the token, colon included.
    pub const fn prefix(self) -> &'static str {
        match self {
            TokenNamespace::MdnsService => "m:",
            TokenNamespace::MdnsTxtKey => "t:",
            TokenNamespace::SsdpTarget => "s:",
            TokenNamespace::SsdpHeader => "h:",
            TokenNamespace::DhcpOptionList => "d:",
            TokenNamespace::VendorClass => "v:",
            TokenNamespace::UserClass => "u:",
            TokenNamespace::Enterprise => "e:",
            TokenNamespace::Flag => "x:",
        }
    }

    /// Whether this namespace contributes to the *core* hash.
    ///
    /// Core is "what protocols do I speak" and must survive a firmware update.
    /// TXT keys and SSDP header names are excluded because vendors add and
    /// remove them freely.
    pub const fn is_core(self) -> bool {
        !matches!(
            self,
            TokenNamespace::MdnsTxtKey | TokenNamespace::SsdpHeader
        )
    }

    /// Recovers the namespace of an already built token.
    pub fn of_token(token: &str) -> Option<Self> {
        const ALL: [TokenNamespace; 9] = [
            TokenNamespace::MdnsService,
            TokenNamespace::MdnsTxtKey,
            TokenNamespace::SsdpTarget,
            TokenNamespace::SsdpHeader,
            TokenNamespace::DhcpOptionList,
            TokenNamespace::VendorClass,
            TokenNamespace::UserClass,
            TokenNamespace::Enterprise,
            TokenNamespace::Flag,
        ];
        ALL.into_iter().find(|ns| token.starts_with(ns.prefix()))
    }
}

/// FNV-1a, 64 bit.
///
/// Hand written on purpose. `std::collections::hash_map::DefaultHasher` is not
/// stable across Rust releases, so every persisted fingerprint would silently
/// change on a toolchain upgrade.
pub const fn fnv1a64(bytes: &[u8]) -> u64 {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    let mut i = 0;
    while i < bytes.len() {
        hash ^= bytes[i] as u64;
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
        i += 1;
    }
    hash
}

/// Lowercases ASCII, drops non-ASCII bytes, and folds separators (rule 1).
///
/// Whitespace and commas become `-`. The catalogue separates tokens with a
/// comma, so a comma inside a token would split one attribute into two on
/// reload. Folding it here means no token can ever hold one.
fn normalize_ascii(value: &str) -> String {
    value
        .chars()
        .filter(|c| c.is_ascii() && !c.is_ascii_control())
        .map(|c| match c {
            ',' => '-',
            c if c.is_ascii_whitespace() => '-',
            c => c.to_ascii_lowercase(),
        })
        .collect()
}

/// Strips a trailing `.` and a trailing `.local` (rule 2).
#[cfg(feature = "mdns")]
fn strip_dns_suffix(value: &str) -> &str {
    let value = value.strip_suffix('.').unwrap_or(value);
    let value = value.strip_suffix(".local").unwrap_or(value);
    value.strip_suffix('.').unwrap_or(value)
}

/// Reduces a DNS-SD name to its service type (rules 2, 3).
///
/// Drops the instance label by keeping the name from the first *label* that
/// starts with `_`, so `living room._googlecast._tcp.local` becomes
/// `_googlecast._tcp`. Matching on the first label, not the first underscore,
/// keeps an instance name that itself contains an underscore from being cut in
/// the wrong place.
#[cfg(feature = "mdns")]
pub(crate) fn service_type_of(name: &str) -> Option<String> {
    let lowered = normalize_ascii(name);
    let name = strip_dns_suffix(&lowered);
    if name.is_empty() {
        return None;
    }
    let mut start = None;
    let mut at_label_start = true;
    for (index, ch) in name.char_indices() {
        if at_label_start && ch == '_' {
            start = Some(index);
            break;
        }
        at_label_start = ch == '.';
    }
    let service = &name[start?..];
    if service.is_empty() {
        None
    } else {
        Some(service.to_string())
    }
}

/// Keeps the key of a `key=value` TXT entry and discards the value (rule 4).
///
/// Values carry firmware versions, serial numbers and user typed names. A
/// valueless entry is a bare flag and is kept whole.
#[cfg(feature = "mdns")]
pub(crate) fn txt_key(entry: &str) -> Option<String> {
    let entry = normalize_ascii(entry);
    let key = match entry.split_once('=') {
        Some((key, _)) => key,
        None => entry.as_str(),
    };
    let key = key.trim();
    if key.is_empty() {
        None
    } else {
        Some(key.to_string())
    }
}

/// Strips a trailing version suffix from a vendor or user class (rule 7).
///
/// `msft 5.0` becomes `msft`, so a firmware bump does not move the device to a
/// new fingerprint. A value that is nothing but digits is left alone, because
/// stripping it would leave an empty token.
pub(crate) fn strip_version_suffix(value: &str) -> &str {
    let bytes = value.as_bytes();
    let mut end = bytes.len();
    let mut saw_digit = false;
    while end > 0 {
        let byte = bytes[end - 1];
        if byte.is_ascii_digit() {
            saw_digit = true;
            end -= 1;
        } else if byte == b'.' {
            end -= 1;
        } else {
            break;
        }
    }
    if !saw_digit || end == 0 {
        return value;
    }
    if end > 0 && matches!(bytes[end - 1], b'-' | b'_' | b' ') {
        end -= 1;
    }
    if end == 0 { value } else { &value[..end] }
}

/// Builds one prefixed token, applying the length cap (§2).
///
/// Returns `None` for an empty value or a token over [`MAX_TOKEN_LEN`]. An
/// over-long token is dropped, never truncated: truncation would map two
/// different attributes onto one token.
pub fn build_token(namespace: TokenNamespace, value: &str) -> Option<String> {
    // A comma would split this token in two when the catalogue is reloaded, so
    // a value still carrying one has escaped normalisation and is refused.
    if value.is_empty() || value.contains(',') {
        return None;
    }
    let mut token = String::with_capacity(namespace.prefix().len() + value.len());
    token.push_str(namespace.prefix());
    token.push_str(value);
    if token.len() > MAX_TOKEN_LEN {
        return None;
    }
    Some(token)
}

/// The attribute set observed for one device (§2).
///
/// Sorted, deduplicated and capped. `BTreeSet` gives the sort and the dedup for
/// free, and makes the cap deterministic: when the set is full the largest
/// token is dropped, so the kept set is the same whatever order packets arrive
/// in.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TokenSet {
    tokens: BTreeSet<String>,
    capped: bool,
}

impl TokenSet {
    /// An empty set.
    pub fn new() -> Self {
        Self::default()
    }

    /// Rebuilds a set from tokens read back out of the database.
    pub fn from_tokens<I, S>(tokens: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let mut set = Self::new();
        for token in tokens {
            set.insert_token(token.into());
        }
        set
    }

    /// Adds `value` under `namespace`, applying the length cap.
    ///
    /// Returns `true` when the token was stored.
    pub fn insert(&mut self, namespace: TokenNamespace, value: &str) -> bool {
        match build_token(namespace, value) {
            Some(token) => self.insert_token(token),
            None => false,
        }
    }

    /// Adds an already prefixed token.
    fn insert_token(&mut self, token: String) -> bool {
        if token.len() > MAX_TOKEN_LEN || TokenNamespace::of_token(&token).is_none() {
            return false;
        }
        if !self.tokens.insert(token) {
            return true;
        }
        if self.tokens.len() > MAX_TOKENS_PER_DEVICE {
            self.tokens.pop_last();
            self.capped = true;
        }
        true
    }

    /// Whether the cap was hit, which makes the set incomplete.
    ///
    /// A capped set is never matched: any similarity score over it would be
    /// measured against tokens that were thrown away.
    pub fn is_capped(&self) -> bool {
        self.capped
    }

    /// The tokens, sorted.
    pub fn tokens(&self) -> impl Iterator<Item = &str> {
        self.tokens.iter().map(String::as_str)
    }

    /// Number of tokens held.
    pub fn len(&self) -> usize {
        self.tokens.len()
    }

    /// Whether the set holds no tokens.
    pub fn is_empty(&self) -> bool {
        self.tokens.is_empty()
    }

    /// Whether `token` is present.
    pub fn contains(&self, token: &str) -> bool {
        self.tokens.contains(token)
    }

    /// The tokens that feed the core hash.
    pub fn core_tokens(&self) -> impl Iterator<Item = &str> {
        self.tokens()
            .filter(|token| TokenNamespace::of_token(token).is_some_and(TokenNamespace::is_core))
    }

    /// The two hashes and the token count (§3).
    pub fn fingerprint(&self) -> Fingerprint {
        Fingerprint {
            core: hash_tokens(self.core_tokens()),
            full: hash_tokens(self.tokens()),
            token_count: self.tokens.len(),
        }
    }
}

/// Hashes tokens joined with `\n`, without building the joined string.
fn hash_tokens<'a, I: Iterator<Item = &'a str>>(tokens: I) -> u64 {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    let mut first = true;
    for token in tokens {
        if !first {
            hash ^= u64::from(b'\n');
            hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
        }
        first = false;
        for byte in token.as_bytes() {
            hash ^= u64::from(*byte);
            hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
        }
    }
    hash
}

/// A device's fingerprint: two hashes and a token count (§3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Fingerprint {
    /// Hash over the core namespaces. Stable across firmware updates.
    pub core: u64,
    /// Hash over every namespace. Tighter, but moves more often.
    pub full: u64,
    /// How many tokens went into `full`.
    pub token_count: usize,
}

impl fmt::Display for Fingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}:{:016x}:{:016x}:{}",
            FINGERPRINT_VERSION, self.core, self.full, self.token_count
        )
    }
}

impl Fingerprint {
    /// Parses a stored fingerprint written by the *current* version.
    ///
    /// A string from an older version returns `None`, which is what triggers
    /// the reset described in §3.
    pub fn parse(value: &str) -> Option<Self> {
        let mut parts = value.split(':');
        if parts.next()? != FINGERPRINT_VERSION {
            return None;
        }
        let core = u64::from_str_radix(parts.next()?, 16).ok()?;
        let full = u64::from_str_radix(parts.next()?, 16).ok()?;
        let token_count = parts.next()?.parse().ok()?;
        if parts.next().is_some() {
            return None;
        }
        Some(Self {
            core,
            full,
            token_count,
        })
    }

    /// The format version a stored string was written with.
    pub fn version_of(value: &str) -> Option<&str> {
        value.split(':').next().filter(|v| !v.is_empty())
    }

    /// Whether a stored string was written by the current version.
    pub fn is_current(value: &str) -> bool {
        Self::version_of(value) == Some(FINGERPRINT_VERSION)
    }
}

/// Whether a device's attribute set may be used for a non-exact match (§6).
///
/// A token set grows as packets arrive. Scoring a half-collected set produces
/// noise, so a core or fuzzy match waits until the set has settled. An exact
/// full-hash match does not need this: a partial set simply fails to match.
pub fn is_ripe(token_count: usize, age_secs: u64, quiet_secs: u64) -> bool {
    token_count >= MIN_TOKENS_FOR_MATCH
        && age_secs >= FINGERPRINT_MIN_AGE_SECS
        && quiet_secs >= FINGERPRINT_QUIET_SECS
}

/// Somewhere a collector can put a token.
///
/// The same collection rules must serve both the plain [`TokenSet`] used by the
/// catalogue and tests, and the timestamped [`AttributeLog`] used by the live
/// capture path. Writing them once behind this trait keeps the two from
/// drifting apart.
pub trait TokenSink {
    /// Offers one attribute value under `namespace`.
    fn accept(&mut self, namespace: TokenNamespace, value: &str);
}

impl TokenSink for TokenSet {
    fn accept(&mut self, namespace: TokenNamespace, value: &str) {
        self.insert(namespace, value);
    }
}

/// Feeds an [`AttributeLog`], stamping every token with the same instant.
struct TimedSink<'a> {
    log: &'a mut AttributeLog,
    now: SystemTime,
}

impl TokenSink for TimedSink<'_> {
    fn accept(&mut self, namespace: TokenNamespace, value: &str) {
        self.log.record(namespace, value, self.now);
    }
}

/// Collects DHCPv4 attributes (§1).
pub fn collect_dhcpv4_into<S: TokenSink>(packet: &Dhcpv4Packet, sink: &mut S) {
    if let Some(list) = &packet.parameter_request_list
        && !list.is_empty()
    {
        // Option 55 keeps its order. The order is the fingerprint. The parts
        // are joined with `-`, not `,`, so the token survives a round trip
        // through the comma separated catalogue field.
        let mut value = String::from("55=");
        for (index, option) in list.iter().enumerate() {
            if index > 0 {
                value.push('-');
            }
            value.push_str(&option.to_string());
        }
        sink.accept(TokenNamespace::DhcpOptionList, &value);
    }

    if let Some(vendor_class) = &packet.vendor_class_id {
        let normalized = normalize_ascii(vendor_class);
        sink.accept(
            TokenNamespace::VendorClass,
            strip_version_suffix(normalized.trim()),
        );
    }

    if packet.vendor_specific_info.is_some() {
        sink.accept(TokenNamespace::Flag, "opt43");
    }
}

/// Collects DHCPv6 attributes (§1).
///
/// Option 16 carries an IANA enterprise number, which is the strongest single
/// token this project can observe: it is assigned, not chosen, and it never
/// changes with firmware.
pub fn collect_dhcpv6_into<S: TokenSink>(options: &[Dhcpv6Option], sink: &mut S) {
    for option in options {
        match option {
            Dhcpv6Option::VendorClass {
                enterprise_number,
                data,
            } => {
                sink.accept(TokenNamespace::Enterprise, &enterprise_number.to_string());
                for entry in data {
                    let normalized = normalize_ascii(entry);
                    sink.accept(
                        TokenNamespace::VendorClass,
                        strip_version_suffix(normalized.trim()),
                    );
                }
            }
            Dhcpv6Option::UserClass(data) => {
                for entry in data {
                    let normalized = normalize_ascii(entry);
                    sink.accept(
                        TokenNamespace::UserClass,
                        strip_version_suffix(normalized.trim()),
                    );
                }
            }
            _ => {}
        }
    }
}

/// Collects mDNS attributes (§1).
///
/// Takes records rather than a packet so the caller passes only the records it
/// has already attributed to this device. A reflected or relayed frame must
/// never reach a fingerprint.
#[cfg(feature = "mdns")]
pub fn collect_mdns_into<S: TokenSink>(records: &[MdnsRecord], sink: &mut S) {
    /// The DNS-SD meta-query. Its PTR target names a service type rather than
    /// an instance, so the service is read from the target, not the name.
    const SERVICE_ENUMERATION: &str = "_services._dns-sd._udp";

    for record in records {
        match (&record.record_type, &record.data) {
            (MdnsRecordType::Ptr, MdnsRecordData::Ptr(target)) => {
                let name = service_type_of(&record.name);
                if name.as_deref() == Some(SERVICE_ENUMERATION) {
                    if let Some(service) = service_type_of(target) {
                        sink.accept(TokenNamespace::MdnsService, &service);
                    }
                } else if let Some(service) = name {
                    sink.accept(TokenNamespace::MdnsService, &service);
                }
            }
            (MdnsRecordType::Srv, _) => {
                if let Some(service) = service_type_of(&record.name) {
                    sink.accept(TokenNamespace::MdnsService, &service);
                }
            }
            (MdnsRecordType::Txt, MdnsRecordData::Txt(entries)) => {
                let Some(service) = service_type_of(&record.name) else {
                    continue;
                };
                sink.accept(TokenNamespace::MdnsService, &service);
                for entry in entries {
                    if let Some(key) = txt_key(entry) {
                        sink.accept(TokenNamespace::MdnsTxtKey, &format!("{}/{}", service, key));
                    }
                }
            }
            // A and AAAA records name a host, not a service. They carry no
            // attribute information, so they contribute no token.
            _ => {}
        }
    }
}

/// Collects SSDP, UPnP and WSD attributes (§1).
#[cfg(feature = "ssdp")]
pub fn collect_ssdp_into<S: TokenSink>(packet: &SsdpPacket, sink: &mut S) {
    for target in ["st", "nt"] {
        if let Some(value) = packet.headers.get(target) {
            let normalized = normalize_ascii(value);
            sink.accept(TokenNamespace::SsdpTarget, normalized.trim());
        }
    }
    for name in packet.headers.keys() {
        let normalized = normalize_ascii(name);
        sink.accept(TokenNamespace::SsdpHeader, normalized.trim());
    }
}

/// One labelled entry of the shared catalogue (§5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FingerprintProfile {
    /// Hash over the profile's core tokens.
    pub core_hash: u64,
    /// Hash over all of the profile's tokens.
    pub full_hash: u64,
    /// Device type to apply, if the profile names one.
    pub device_type: Option<DeviceType>,
    /// Vendor to apply, if the profile names one.
    pub vendor: Option<Vendor>,
    /// Human readable name shown in the UI.
    pub label: String,
    /// Whether this is a copied default profile rather than a real product.
    pub generic: bool,
    /// The tokens this profile was built from, so a reviewer can check it.
    pub tokens: Vec<String>,
    /// How many distinct units this hash has been seen on.
    pub observations: u32,
    /// How many distinct OUI vendors those units had.
    pub oui_count: u32,
}

/// Why a catalogue line was skipped. Counted, not logged one by one.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CatalogueSkips {
    /// Line longer than [`MAX_CATALOGUE_LINE`].
    pub too_long: u32,
    /// Field count other than seven.
    pub bad_field_count: u32,
    /// Empty token list, or no token that parsed.
    pub no_tokens: u32,
    /// Stored hash did not match the hash recomputed from the tokens.
    pub hash_mismatch: u32,
}

impl CatalogueSkips {
    /// Total number of skipped lines.
    pub fn total(&self) -> u32 {
        self.too_long + self.bad_field_count + self.no_tokens + self.hash_mismatch
    }

    /// Whether every line was accepted.
    pub fn is_empty(&self) -> bool {
        self.total() == 0
    }
}

/// The result of matching a device against the catalogue (§6).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FingerprintMatch {
    /// Human readable name of the matched profile.
    pub label: String,
    /// Device type the profile names, if any.
    pub device_type: Option<DeviceType>,
    /// Vendor the profile names, if any.
    pub vendor: Option<Vendor>,
    /// Confidence from 0 to 99. Never 100: a fingerprint is evidence, not proof.
    pub confidence: u8,
    /// Whether the matched profile is a copied default.
    pub generic: bool,
}

/// The loaded profile catalogue (§5).
#[derive(Debug, Clone, Default)]
pub struct FingerprintCatalogue {
    profiles: Vec<FingerprintProfile>,
    by_core: HashMap<u64, usize>,
    by_full: HashMap<u64, usize>,
    token_index: HashMap<String, Vec<usize>>,
}

impl FingerprintCatalogue {
    /// An empty catalogue.
    ///
    /// The feature works with zero profiles: no match simply means the existing
    /// heuristics run, exactly as they do today.
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of loaded profiles.
    pub fn len(&self) -> usize {
        self.profiles.len()
    }

    /// Whether no profile is loaded.
    pub fn is_empty(&self) -> bool {
        self.profiles.is_empty()
    }

    /// The loaded profiles.
    pub fn profiles(&self) -> &[FingerprintProfile] {
        &self.profiles
    }

    /// Loads a catalogue file, returning the accepted count and the skip tally.
    ///
    /// A malformed line never aborts the load. This mirrors
    /// [`crate::oui::OuiRegistry::load_from_file`] so operators see one
    /// consistent loader.
    pub fn load_from_file<P: AsRef<Path>>(
        &mut self,
        path: P,
    ) -> std::io::Result<(usize, CatalogueSkips)> {
        let reader = BufReader::new(File::open(path)?);
        let mut accepted = 0;
        let mut skips = CatalogueSkips::default();

        for line in reader.lines() {
            let line = line?;
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') || line.starts_with("//") {
                continue;
            }
            if line.len() > MAX_CATALOGUE_LINE {
                skips.too_long += 1;
                continue;
            }
            match Self::parse_line(line) {
                Ok(profile) => {
                    self.insert(profile);
                    accepted += 1;
                }
                Err(reason) => match reason {
                    SkipReason::BadFieldCount => skips.bad_field_count += 1,
                    SkipReason::NoTokens => skips.no_tokens += 1,
                    SkipReason::HashMismatch => skips.hash_mismatch += 1,
                },
            }
        }

        self.rebuild_index();
        Ok((accepted, skips))
    }

    /// Adds one profile, replacing any earlier profile with the same core hash.
    ///
    /// Last wins, matching the OUI loader's `HashMap::insert` behaviour.
    pub fn insert(&mut self, profile: FingerprintProfile) {
        if let Some(&index) = self.by_core.get(&profile.core_hash) {
            self.profiles[index] = profile;
        } else {
            self.by_core.insert(profile.core_hash, self.profiles.len());
            self.profiles.push(profile);
        }
    }

    /// Parses one non-comment catalogue line.
    fn parse_line(line: &str) -> Result<FingerprintProfile, SkipReason> {
        let fields: Vec<&str> = line.split('\t').map(str::trim).collect();
        if fields.len() != CATALOGUE_FIELDS {
            return Err(SkipReason::BadFieldCount);
        }

        let stored_hash =
            u64::from_str_radix(fields[0], 16).map_err(|_| SkipReason::HashMismatch)?;

        let tokens = TokenSet::from_tokens(
            fields[5]
                .split(',')
                .map(str::trim)
                .filter(|token| !token.is_empty()),
        );
        if tokens.is_empty() {
            return Err(SkipReason::NoTokens);
        }

        // The hash is derived from the tokens, so it is recomputable. A line
        // whose stored hash disagrees with its own tokens is rejected: one of
        // the two is wrong and there is no way to tell which.
        let fingerprint = tokens.fingerprint();
        if fingerprint.core != stored_hash {
            return Err(SkipReason::HashMismatch);
        }

        let (observations, oui_count) = parse_meta(fields[6]);
        Ok(FingerprintProfile {
            core_hash: fingerprint.core,
            full_hash: fingerprint.full,
            // `-` is checked before the conversion. Without that check it would
            // become `DeviceType::Other("-")` and show up in the UI.
            device_type: unset_or(fields[1]).map(DeviceType::from),
            vendor: unset_or(fields[2]).map(Vendor::from),
            label: unset_or(fields[3]).unwrap_or("Unknown profile").to_string(),
            generic: fields[4]
                .split(',')
                .any(|flag| flag.trim().eq_ignore_ascii_case("generic"))
                || oui_count >= GENERIC_OUI_THRESHOLD,
            tokens: tokens.tokens().map(str::to_string).collect(),
            observations,
            oui_count,
        })
    }

    /// Rebuilds the lookup maps and the rare-token index (§6).
    fn rebuild_index(&mut self) {
        self.by_core.clear();
        self.by_full.clear();
        let mut counts: HashMap<&str, usize> = HashMap::new();
        for (index, profile) in self.profiles.iter().enumerate() {
            self.by_core.insert(profile.core_hash, index);
            self.by_full.insert(profile.full_hash, index);
            for token in &profile.tokens {
                *counts.entry(token.as_str()).or_default() += 1;
            }
        }

        // Boilerplate like `h:server` reaches nearly every profile, so probing
        // it would defeat the index. Common tokens still count inside the
        // Jaccard score; they just do not select candidates.
        let limit = rare_token_limit(self.profiles.len());
        let rare: BTreeSet<String> = counts
            .into_iter()
            .filter(|&(_, count)| count <= limit)
            .map(|(token, _)| token.to_string())
            .collect();

        self.token_index.clear();
        for (index, profile) in self.profiles.iter().enumerate() {
            for token in &profile.tokens {
                if rare.contains(token) {
                    self.token_index
                        .entry(token.clone())
                        .or_default()
                        .push(index);
                }
            }
        }
    }

    /// Matches a device's attribute set against the catalogue (§6).
    ///
    /// `ripe` gates the core and fuzzy paths only; see [`is_ripe`]. `oui_vendor`
    /// is the vendor the MAC prefix resolved to, used as corroboration.
    pub fn match_tokens(
        &self,
        set: &TokenSet,
        ripe: bool,
        oui_vendor: Option<&Vendor>,
    ) -> Option<FingerprintMatch> {
        // A capped set is missing tokens by definition, so every score over it
        // would be measured against attributes that were thrown away.
        if set.is_capped() || set.is_empty() || self.profiles.is_empty() {
            return None;
        }

        let fingerprint = set.fingerprint();

        if let Some(&index) = self.by_full.get(&fingerprint.full) {
            return Some(self.build_match(index, 95, oui_vendor));
        }
        if !ripe {
            return None;
        }
        if let Some(&index) = self.by_core.get(&fingerprint.core) {
            return Some(self.build_match(index, 85, oui_vendor));
        }

        let (index, similarity) = self.best_fuzzy(set)?;
        if similarity < 0.60 {
            return None;
        }
        let score = (similarity * 80.0).round() as u8;
        Some(self.build_match(index, score, oui_vendor))
    }

    /// Finds the best fuzzy candidate and its Jaccard similarity.
    fn best_fuzzy(&self, set: &TokenSet) -> Option<(usize, f32)> {
        let device: BTreeSet<&str> = set.core_tokens().collect();
        if device.is_empty() {
            return None;
        }

        // Only profiles sharing a rare token are scored. A device with no rare
        // token at all is pure boilerplate, which is exactly the case this
        // design must refuse to guess at.
        let mut candidates: BTreeSet<usize> = BTreeSet::new();
        for token in &device {
            if let Some(indices) = self.token_index.get(*token) {
                candidates.extend(indices);
            }
        }

        let mut best: Option<(usize, f32)> = None;
        for index in candidates {
            let profile: BTreeSet<&str> = self.profiles[index]
                .tokens
                .iter()
                .map(String::as_str)
                .filter(|token| {
                    TokenNamespace::of_token(token).is_some_and(TokenNamespace::is_core)
                })
                .collect();
            let shared = device.intersection(&profile).count();
            let total = device.union(&profile).count();
            if total == 0 {
                continue;
            }
            let similarity = shared as f32 / total as f32;
            if best.is_none_or(|(_, current)| similarity > current) {
                best = Some((index, similarity));
            }
        }
        best
    }

    /// Applies the confidence adjustments and builds the result.
    fn build_match(&self, index: usize, base: u8, oui_vendor: Option<&Vendor>) -> FingerprintMatch {
        let profile = &self.profiles[index];
        let mut score = i32::from(base);
        if let (Some(observed), Some(expected)) = (oui_vendor, profile.vendor.as_ref())
            && observed == expected
        {
            score += 10;
        }
        if profile.generic {
            score -= 25;
        }
        let confidence = score.clamp(0, 99) as u8;
        FingerprintMatch {
            label: profile.label.clone(),
            // A generic profile never sets a device type (§7). It is a copied
            // default, so its type says nothing about this device.
            device_type: if profile.generic {
                None
            } else {
                profile.device_type.clone()
            },
            vendor: if profile.generic {
                None
            } else {
                profile.vendor.clone()
            },
            confidence,
            generic: profile.generic,
        }
    }
}

/// Why [`FingerprintCatalogue::parse_line`] rejected a line.
enum SkipReason {
    BadFieldCount,
    NoTokens,
    HashMismatch,
}

/// How many profiles a token may appear in and still count as rare.
///
/// Always at least one, so a small catalogue still indexes something.
fn rare_token_limit(profile_count: usize) -> usize {
    ((profile_count as f32 * RARE_TOKEN_MAX_SHARE).floor() as usize).max(1)
}

/// Maps the `-` placeholder to `None`.
fn unset_or(field: &str) -> Option<&str> {
    if field.is_empty() || field == UNSET {
        None
    } else {
        Some(field)
    }
}

/// Reads `n=<observations>,oui=<vendors>` from the catalogue `meta` field.
///
/// An absent or malformed key means "one unit, one vendor", which is the
/// weakest honest reading of a line somebody wrote by hand.
fn parse_meta(field: &str) -> (u32, u32) {
    let mut observations = 1;
    let mut oui_count = 1;
    for part in field.split(',') {
        let Some((key, value)) = part.trim().split_once('=') else {
            continue;
        };
        let Ok(parsed) = value.trim().parse::<u32>() else {
            continue;
        };
        match key.trim() {
            "n" => observations = parsed,
            "oui" => oui_count = parsed,
            _ => {}
        }
    }
    (observations, oui_count)
}

/// When a token was first and last advertised.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TokenTimes {
    /// When this token was first seen for the device.
    pub first_seen: SystemTime,
    /// When this token was last seen for the device.
    pub last_seen: SystemTime,
}

/// One device's attribute set with the timestamps the database keeps (§4).
///
/// [`TokenSet`] stays free of time so a catalogue profile can use it too. This
/// wrapper adds the bookkeeping the live capture path needs: when each token
/// was first and last advertised, which drives both the quiet-period part of
/// the ripeness rule (§6) and the stale-token prune (§4).
#[derive(Debug, Clone, Default)]
pub struct AttributeLog {
    set: TokenSet,
    times: BTreeMap<String, TokenTimes>,
    newest_at: Option<SystemTime>,
}

impl AttributeLog {
    /// An empty log.
    pub fn new() -> Self {
        Self::default()
    }

    /// Records an observation, returning `true` when the token is new.
    ///
    /// A token already held only has its `last_seen` refreshed, so re-hearing a
    /// service does not restart the device's quiet period.
    pub fn record(&mut self, namespace: TokenNamespace, value: &str, now: SystemTime) -> bool {
        let Some(token) = build_token(namespace, value) else {
            return false;
        };
        if let Some(times) = self.times.get_mut(&token) {
            times.last_seen = now;
            return false;
        }
        self.set.insert(namespace, value);
        self.times.insert(
            token,
            TokenTimes {
                first_seen: now,
                last_seen: now,
            },
        );
        self.sync_with_set();
        self.newest_at = Some(now);
        true
    }

    /// Restores one token read back from the database.
    pub fn restore(&mut self, token: &str, first_seen: SystemTime, last_seen: SystemTime) {
        if !self.set.insert_token(token.to_string()) {
            return;
        }
        self.times.insert(
            token.to_string(),
            TokenTimes {
                first_seen,
                last_seen,
            },
        );
        self.sync_with_set();
        self.newest_at = Some(match self.newest_at {
            Some(current) if current >= first_seen => current,
            _ => first_seen,
        });
    }

    /// Drops timestamps for tokens the cap evicted from the set.
    ///
    /// [`TokenSet`] owns the cap rule. Mirroring its membership here keeps that
    /// rule in one place instead of restating it.
    fn sync_with_set(&mut self) {
        if self.times.len() <= self.set.len() {
            return;
        }
        let set = &self.set;
        self.times.retain(|token, _| set.contains(token));
    }

    /// The tokens and their hashes.
    pub fn set(&self) -> &TokenSet {
        &self.set
    }

    /// Every token with its timestamps, sorted by token.
    pub fn entries(&self) -> impl Iterator<Item = (&str, TokenTimes)> {
        self.times
            .iter()
            .map(|(token, times)| (token.as_str(), *times))
    }

    /// When the newest token appeared, used by the quiet-period rule (§6).
    pub fn newest_at(&self) -> Option<SystemTime> {
        self.newest_at
    }

    /// Number of tokens held.
    pub fn len(&self) -> usize {
        self.times.len()
    }

    /// Whether the log holds no tokens.
    pub fn is_empty(&self) -> bool {
        self.times.is_empty()
    }

    /// Removes tokens last advertised more than [`TOKEN_STALE_DAYS`] before
    /// `reference`, returning the removed tokens (§4).
    ///
    /// `reference` is the **device's own** `last_seen`, not the wall clock. A
    /// device that has been offline for a year keeps its whole set frozen;
    /// only a device that is still active, but has stopped advertising a
    /// service, loses that token.
    pub fn prune_stale(&mut self, reference: SystemTime) -> Vec<String> {
        let window = Duration::from_secs(TOKEN_STALE_DAYS as u64 * 24 * 60 * 60);
        let Some(cutoff) = reference.checked_sub(window) else {
            return Vec::new();
        };
        let stale: Vec<String> = self
            .times
            .iter()
            .filter(|(_, times)| times.last_seen < cutoff)
            .map(|(token, _)| token.clone())
            .collect();
        if stale.is_empty() {
            return stale;
        }
        for token in &stale {
            self.times.remove(token);
        }
        self.set = TokenSet::from_tokens(self.times.keys().cloned());
        self.newest_at = self.times.values().map(|times| times.first_seen).max();
        stale
    }

    /// Whether this log may be used for a core or fuzzy match (§6).
    ///
    /// `device_first_seen` and `now` come from the caller because the log does
    /// not know when the device itself was discovered.
    pub fn is_ripe_at(&self, device_first_seen: SystemTime, now: SystemTime) -> bool {
        let age = now
            .duration_since(device_first_seen)
            .unwrap_or_default()
            .as_secs();
        let quiet = match self.newest_at {
            Some(newest) => now.duration_since(newest).unwrap_or_default().as_secs(),
            None => return false,
        };
        is_ripe(self.len(), age, quiet)
    }
}

/// Collects DHCPv4 attributes into a plain token set.
pub fn collect_dhcpv4_tokens(packet: &Dhcpv4Packet, set: &mut TokenSet) {
    collect_dhcpv4_into(packet, set);
}

/// Collects DHCPv4 attributes into a timestamped log.
pub fn collect_dhcpv4_attributes(packet: &Dhcpv4Packet, log: &mut AttributeLog, now: SystemTime) {
    collect_dhcpv4_into(packet, &mut TimedSink { log, now });
}

/// Collects DHCPv6 attributes into a plain token set.
pub fn collect_dhcpv6_tokens(options: &[Dhcpv6Option], set: &mut TokenSet) {
    collect_dhcpv6_into(options, set);
}

/// Collects DHCPv6 attributes into a timestamped log.
pub fn collect_dhcpv6_attributes(
    options: &[Dhcpv6Option],
    log: &mut AttributeLog,
    now: SystemTime,
) {
    collect_dhcpv6_into(options, &mut TimedSink { log, now });
}

/// Collects mDNS attributes into a plain token set.
#[cfg(feature = "mdns")]
pub fn collect_mdns_tokens(records: &[MdnsRecord], set: &mut TokenSet) {
    collect_mdns_into(records, set);
}

/// Collects mDNS attributes into a timestamped log.
#[cfg(feature = "mdns")]
pub fn collect_mdns_attributes(records: &[MdnsRecord], log: &mut AttributeLog, now: SystemTime) {
    collect_mdns_into(records, &mut TimedSink { log, now });
}

/// Collects SSDP attributes into a plain token set.
#[cfg(feature = "ssdp")]
pub fn collect_ssdp_tokens(packet: &SsdpPacket, set: &mut TokenSet) {
    collect_ssdp_into(packet, set);
}

/// Collects SSDP attributes into a timestamped log.
#[cfg(feature = "ssdp")]
pub fn collect_ssdp_attributes(packet: &SsdpPacket, log: &mut AttributeLog, now: SystemTime) {
    collect_ssdp_into(packet, &mut TimedSink { log, now });
}
