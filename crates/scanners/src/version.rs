//! Tolerant version parsing and comparison for CVE correlation.
//!
//! Service banners carry messy version strings: `1.18.0`, `8.9p1`, `2.4.52`,
//! `1.1.1f`, `7.4`, `v2.3.4`. We need to compare these against CVE version
//! ranges (NVD-style inclusive/exclusive bounds) *correctly* — string
//! comparison is wrong (`1.9` < `1.10` numerically but not lexically), and this
//! is the single most accuracy-sensitive piece of the correlation feature.
//!
//! The approach: split a version into an ordered list of numeric components
//! plus an optional trailing "suffix" (letters/patch markers like `p1`, `f`,
//! `beta`). Numeric components compare numerically; a missing component is
//! treated as 0 (so `1.18` == `1.18.0`). Suffixes are compared only when the
//! numeric parts are equal, lexically, with "no suffix" sorting *before* any
//! suffix (so `1.1.1` < `1.1.1f`), matching how OpenSSL-style letter patches
//! and OpenSSH `pN` patch levels order in practice.
//!
//! This is deliberately conservative and well-tested rather than clever.

use std::cmp::Ordering;

/// A parsed, comparable version.
///
/// `PartialEq`/`Eq` are defined in terms of [`Ord`] (not derived) so that
/// `1.18` and `1.18.0` are equal — consistent with comparison, which zero-fills
/// missing components. Deriving would make them structurally unequal.
#[derive(Debug, Clone)]
pub struct Version {
    /// Numeric components, most-significant first (e.g. [1, 18, 0]).
    numeric: Vec<u64>,
    /// Trailing non-numeric marker, lowercased (e.g. "p1", "f", "beta"), if any.
    suffix: Option<String>,
}

impl PartialEq for Version {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other) == Ordering::Equal
    }
}
impl Eq for Version {}

impl Version {
    /// Parse a version string tolerantly. Returns `None` only if there is no
    /// leading numeric component at all (e.g. "unknown", "").
    pub fn parse(raw: &str) -> Option<Version> {
        let s = raw.trim().trim_start_matches(['v', 'V']);
        if s.is_empty() {
            return None;
        }

        // Walk the string splitting into numeric runs separated by '.'/'-'/'_',
        // capturing the first non-numeric trailing chunk as the suffix.
        let mut numeric: Vec<u64> = Vec::new();
        let mut suffix: Option<String> = None;

        // Split on common separators first.
        let mut chars = s.chars().peekable();
        let mut cur = String::new();

        // Helper closure replaced by an explicit loop to keep ownership simple.
        let flush_component = |cur: &mut String,
                               numeric: &mut Vec<u64>,
                               suffix: &mut Option<String>| {
            if cur.is_empty() {
                return;
            }
            // A component like "1" -> numeric; "1f"/"8p1" -> numeric prefix +
            // suffix; "beta" -> pure suffix.
            let digits: String = cur.chars().take_while(|c| c.is_ascii_digit()).collect();
            if digits.is_empty() {
                // Pure non-numeric component: it's a suffix (keep the first).
                if suffix.is_none() {
                    *suffix = Some(cur.to_ascii_lowercase());
                }
            } else {
                if let Ok(n) = digits.parse::<u64>() {
                    numeric.push(n);
                }
                let rest: String = cur[digits.len()..].to_string();
                if !rest.is_empty() && suffix.is_none() {
                    *suffix = Some(rest.to_ascii_lowercase());
                }
            }
            cur.clear();
        };

        while let Some(&c) = chars.peek() {
            if c == '.' || c == '-' || c == '_' {
                flush_component(&mut cur, &mut numeric, &mut suffix);
                chars.next();
            } else {
                cur.push(c);
                chars.next();
            }
        }
        flush_component(&mut cur, &mut numeric, &mut suffix);

        if numeric.is_empty() {
            return None;
        }
        Some(Version { numeric, suffix })
    }
}

impl PartialOrd for Version {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Version {
    fn cmp(&self, other: &Self) -> Ordering {
        // Compare numeric components position by position; a missing component
        // is treated as 0 so 1.18 == 1.18.0.
        let max = self.numeric.len().max(other.numeric.len());
        for i in 0..max {
            let a = self.numeric.get(i).copied().unwrap_or(0);
            let b = other.numeric.get(i).copied().unwrap_or(0);
            match a.cmp(&b) {
                Ordering::Equal => continue,
                non_eq => return non_eq,
            }
        }
        // Numeric parts equal: no-suffix sorts before any suffix; otherwise
        // compare suffixes lexically (lowercased already).
        match (&self.suffix, &other.suffix) {
            (None, None) => Ordering::Equal,
            (None, Some(_)) => Ordering::Less,
            (Some(_), None) => Ordering::Greater,
            (Some(a), Some(b)) => a.cmp(b),
        }
    }
}

/// A version range with optional inclusive/exclusive bounds, mirroring NVD's
/// `versionStartIncluding` / `versionStartExcluding` / `versionEndIncluding` /
/// `versionEndExcluding` semantics. An absent bound means "unbounded" on that
/// side. An exact single version is expressed as `start=end` both inclusive.
#[derive(Debug, Clone, Default)]
pub struct VersionRange {
    pub start_including: Option<Version>,
    pub start_excluding: Option<Version>,
    pub end_including: Option<Version>,
    pub end_excluding: Option<Version>,
}

impl VersionRange {
    /// A range that matches exactly one version.
    pub fn exact(v: &str) -> VersionRange {
        let ver = Version::parse(v);
        VersionRange {
            start_including: ver.clone(),
            end_including: ver,
            ..Default::default()
        }
    }

    /// `[start, end)` — start inclusive, end exclusive (the most common CVE shape).
    pub fn from_until(start_incl: &str, end_excl: &str) -> VersionRange {
        VersionRange {
            start_including: Version::parse(start_incl),
            end_excluding: Version::parse(end_excl),
            ..Default::default()
        }
    }

    /// `(-inf, end)` — everything below `end_excl`.
    pub fn below(end_excl: &str) -> VersionRange {
        VersionRange {
            end_excluding: Version::parse(end_excl),
            ..Default::default()
        }
    }

    /// `[start, +inf)` — everything at or above `start_incl`.
    pub fn at_least(start_incl: &str) -> VersionRange {
        VersionRange {
            start_including: Version::parse(start_incl),
            ..Default::default()
        }
    }

    /// Does `v` fall within this range?
    pub fn contains(&self, v: &Version) -> bool {
        if let Some(si) = &self.start_including {
            if v < si {
                return false;
            }
        }
        if let Some(se) = &self.start_excluding {
            if v <= se {
                return false;
            }
        }
        if let Some(ei) = &self.end_including {
            if v > ei {
                return false;
            }
        }
        if let Some(ee) = &self.end_excluding {
            if v >= ee {
                return false;
            }
        }
        true
    }

    /// Convenience: parse `raw` and test containment. Unparseable -> false.
    pub fn matches_str(&self, raw: &str) -> bool {
        match Version::parse(raw) {
            Some(v) => self.contains(&v),
            None => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(s: &str) -> Version {
        Version::parse(s).unwrap_or_else(|| panic!("failed to parse {s}"))
    }

    #[test]
    fn parses_basic() {
        let a = v("1.18.0");
        assert_eq!(a.numeric, vec![1, 18, 0]);
        assert!(a.suffix.is_none());
    }

    #[test]
    fn strips_leading_v() {
        assert_eq!(v("v2.3.4"), v("2.3.4"));
    }

    #[test]
    fn numeric_not_lexical_ordering() {
        assert!(v("1.9") < v("1.10"));
        assert!(v("2.0") > v("1.99"));
    }

    #[test]
    fn missing_components_are_zero() {
        // PartialEq is Ord-consistent, so zero-fill makes these equal.
        assert_eq!(v("1.18"), v("1.18.0"));
        assert!(v("1.18") < v("1.18.1"));
    }

    #[test]
    fn openssh_patch_suffix() {
        // 8.9p1 parses to numeric [8,9] + suffix "p1".
        let a = v("8.9p1");
        assert_eq!(a.numeric, vec![8, 9]);
        assert_eq!(a.suffix.as_deref(), Some("p1"));
        // No suffix sorts before a suffix at the same numeric level.
        assert!(v("8.9") < v("8.9p1"));
        assert!(v("8.9p1") < v("8.9p2"));
    }

    #[test]
    fn openssl_letter_suffix() {
        // 1.1.1f -> numeric [1,1,1] + suffix "f".
        assert!(v("1.1.1") < v("1.1.1f"));
        assert!(v("1.1.1f") < v("1.1.1g"));
        assert!(v("1.1.1f") < v("1.1.2"));
    }

    #[test]
    fn unparseable_is_none() {
        assert!(Version::parse("").is_none());
        assert!(Version::parse("unknown").is_none());
        assert!(Version::parse("   ").is_none());
    }

    #[test]
    fn range_from_until_exclusive_end() {
        let r = VersionRange::from_until("2.4.0", "2.4.52");
        assert!(r.matches_str("2.4.0")); // start inclusive
        assert!(r.matches_str("2.4.51"));
        assert!(!r.matches_str("2.4.52")); // end exclusive
        assert!(!r.matches_str("2.3.9"));
        assert!(!r.matches_str("2.5.0"));
    }

    #[test]
    fn range_exact() {
        let r = VersionRange::exact("2.3.4");
        assert!(r.matches_str("2.3.4"));
        assert!(!r.matches_str("2.3.3"));
        assert!(!r.matches_str("2.3.5"));
        // 2.3.4 == 2.3.4.0 via zero-fill
        assert!(r.matches_str("2.3.4.0"));
    }

    #[test]
    fn range_below_and_at_least() {
        let below = VersionRange::below("9.6");
        assert!(below.matches_str("7.4"));
        assert!(below.matches_str("9.5"));
        assert!(!below.matches_str("9.6"));
        assert!(!below.matches_str("10.0"));

        let atleast = VersionRange::at_least("1.1.1");
        assert!(atleast.matches_str("1.1.1"));
        assert!(atleast.matches_str("3.0.0"));
        assert!(!atleast.matches_str("1.1.0"));
    }

    #[test]
    fn range_unparseable_version_is_false() {
        let r = VersionRange::from_until("1.0", "2.0");
        assert!(!r.matches_str("unknown"));
        assert!(!r.matches_str(""));
    }

    #[test]
    fn suffix_only_within_numeric_equal() {
        // Suffix must not override numeric ordering: 1.0f is still < 2.0.
        assert!(v("1.0f") < v("2.0"));
        assert!(v("2.0") > v("1.9z"));
    }
}
