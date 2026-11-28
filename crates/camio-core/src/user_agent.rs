//! Realistic, blend-in User-Agent generation (plan §6 "Fingerprint
//! transparency").
//!
//! The guiding principle here is the same one the rest of the fingerprint layer
//! follows: **a unique "stealth" identity is itself a fingerprint**. The way to
//! not stand out is to look like one of the many — to draw a User-Agent (and the
//! browser family it implies) from the *common* end of the real-world
//! distribution, weighted by actual market share, so a scraped request blends
//! into the largest possible anonymity set.
//!
//! Two rules make this safe rather than a tell:
//!   1. **Coherent, not random-per-field.** Each entry is a real UA string paired
//!      with the [`BrowserFamily`] and [`UaOs`] it genuinely implies, so a caller
//!      can match the TLS/HTTP-2 impersonation to the family (`camio-request`).
//!      A Chrome UA sent over a Firefox TLS stack is a classic detection — this
//!      module hands out the family so that can't happen by accident.
//!   2. **Current, not stale.** The pool tracks recent stable versions; an
//!      obviously old UA (a Firefox from three years ago) is anomalous and
//!      easier to flag than a current one.
//!
//! Selection is deterministic from a seed (see [`crate::rng`]) so an identity
//! can be pinned and reproduced.

use crate::rng::SplitMix64;
use serde::{Deserialize, Serialize};

/// The browser engine family a UA implies. Callers match their TLS/HTTP-2
/// impersonation to this so the network fingerprint agrees with the UA string.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BrowserFamily {
    Firefox,
    Chrome,
    Safari,
    Edge,
}

impl BrowserFamily {
    pub fn as_str(self) -> &'static str {
        match self {
            BrowserFamily::Firefox => "firefox",
            BrowserFamily::Chrome => "chrome",
            BrowserFamily::Safari => "safari",
            BrowserFamily::Edge => "edge",
        }
    }
}

/// The OS a UA presents.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UaOs {
    Windows,
    Macos,
    Linux,
    Android,
    Ios,
}

impl UaOs {
    pub fn as_str(self) -> &'static str {
        match self {
            UaOs::Windows => "windows",
            UaOs::Macos => "macos",
            UaOs::Linux => "linux",
            UaOs::Android => "android",
            UaOs::Ios => "ios",
        }
    }
}

/// One curated User-Agent: the string plus the family/OS/version it implies and
/// a relative real-world frequency weight.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UserAgent {
    pub string: String,
    pub family: BrowserFamily,
    pub os: UaOs,
    /// The browser's major version, so callers can keep other fingerprint
    /// fields (Sec-CH-UA, navigator.appVersion) consistent with the UA.
    pub major_version: u32,
}

/// A static pool entry (borrowed form of [`UserAgent`]) with a selection weight.
struct Entry {
    string: &'static str,
    family: BrowserFamily,
    os: UaOs,
    major_version: u32,
    /// Relative frequency weight (roughly tracks global desktop+mobile share;
    /// Chrome dominates, Safari is iOS-heavy, Firefox/Edge trail). The exact
    /// numbers matter less than the ordering — the point is to make the common
    /// browsers common and the rare ones rare.
    weight: u32,
}

impl Entry {
    fn to_owned(&self) -> UserAgent {
        UserAgent {
            string: self.string.to_string(),
            family: self.family,
            os: self.os,
            major_version: self.major_version,
        }
    }
}

use BrowserFamily::*;
use UaOs::*;

/// The curated pool. Versions track recent stable releases as of the crate's
/// alignment date; bump them when [`crate::ALIGNED_FIREFOX_MAJOR`] and the
/// impersonation targets move. Weights approximate real global share so the
/// generator blends into the majority.
static POOL: &[Entry] = &[
    // --- Chrome (the global majority; Windows-heavy) --------------------------
    Entry {
        string: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36",
        family: Chrome, os: Windows, major_version: 142, weight: 300,
    },
    Entry {
        string: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36",
        family: Chrome, os: Windows, major_version: 141, weight: 120,
    },
    Entry {
        string: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36",
        family: Chrome, os: Macos, major_version: 142, weight: 90,
    },
    Entry {
        string: "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36",
        family: Chrome, os: Linux, major_version: 142, weight: 40,
    },
    // --- Safari (iOS + macOS; big on mobile) ----------------------------------
    Entry {
        string: "Mozilla/5.0 (iPhone; CPU iPhone OS 18_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Mobile/15E148 Safari/604.1",
        family: Safari, os: Ios, major_version: 18, weight: 150,
    },
    Entry {
        string: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Safari/605.1.15",
        family: Safari, os: Macos, major_version: 18, weight: 70,
    },
    // --- Chrome on Android (huge mobile share) --------------------------------
    Entry {
        string: "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Mobile Safari/537.36",
        family: Chrome, os: Android, major_version: 142, weight: 130,
    },
    Entry {
        string: "Mozilla/5.0 (Linux; Android 14; SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Mobile Safari/537.36",
        family: Chrome, os: Android, major_version: 142, weight: 80,
    },
    // --- Edge (Windows-centric) ----------------------------------------------
    Entry {
        string: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36 Edg/142.0.0.0",
        family: Edge, os: Windows, major_version: 142, weight: 60,
    },
    // --- Firefox (the family Camio's own managed browser uses) ----------------
    Entry {
        string: "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:158.0) Gecko/20100101 Firefox/158.0",
        family: Firefox, os: Windows, major_version: 158, weight: 45,
    },
    Entry {
        string: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:158.0) Gecko/20100101 Firefox/158.0",
        family: Firefox, os: Macos, major_version: 158, weight: 15,
    },
    Entry {
        string: "Mozilla/5.0 (X11; Linux x86_64; rv:158.0) Gecko/20100101 Firefox/158.0",
        family: Firefox, os: Linux, major_version: 158, weight: 20,
    },
];

/// Pick a realistic User-Agent, weighted by real-world frequency, deterministic
/// from `seed`.
pub fn random_user_agent(seed: u64) -> UserAgent {
    let mut rng = SplitMix64::new(seed);
    pick(&mut rng)
}

/// Pick a realistic User-Agent from a one-off, non-reproducible seed.
pub fn random_user_agent_from_entropy() -> UserAgent {
    let mut rng = SplitMix64::from_entropy();
    pick(&mut rng)
}

fn pick(rng: &mut SplitMix64) -> UserAgent {
    let weights: Vec<u32> = POOL.iter().map(|e| e.weight).collect();
    let idx = rng.weighted_index(&weights);
    POOL[idx].to_owned()
}

/// Pick a realistic User-Agent restricted to one browser family (e.g. only
/// Firefox, to match the managed browser's engine). Falls back to the whole
/// pool if the family has no entries (never, for the built-in pool).
pub fn random_user_agent_for(seed: u64, family: BrowserFamily) -> UserAgent {
    let mut rng = SplitMix64::new(seed);
    let filtered: Vec<&Entry> = POOL.iter().filter(|e| e.family == family).collect();
    if filtered.is_empty() {
        return pick(&mut rng);
    }
    let weights: Vec<u32> = filtered.iter().map(|e| e.weight).collect();
    let idx = rng.weighted_index(&weights);
    filtered[idx].to_owned()
}

/// A rotation helper: hands out UAs for a sequence of requests, either picking a
/// fresh weighted-random one each call, or keeping one **sticky per host** so a
/// single site sees a single, consistent identity across a session (rotating UA
/// mid-session on one host is itself a detectable anomaly).
#[derive(Debug, Clone)]
pub struct UserAgentRotator {
    rng: SplitMix64,
    sticky: Vec<(String, UserAgent)>,
    family: Option<BrowserFamily>,
}

impl UserAgentRotator {
    /// A rotator seeded for reproducibility, drawing from the whole pool.
    pub fn new(seed: u64) -> Self {
        UserAgentRotator {
            rng: SplitMix64::new(seed),
            sticky: Vec::new(),
            family: None,
        }
    }

    /// Restrict the rotator to one browser family (e.g. to stay consistent with
    /// a Firefox engine).
    pub fn with_family(mut self, family: BrowserFamily) -> Self {
        self.family = Some(family);
        self
    }

    fn pick_now(&mut self) -> UserAgent {
        let candidates: Vec<&Entry> = match self.family {
            Some(f) => POOL.iter().filter(|e| e.family == f).collect(),
            None => POOL.iter().collect(),
        };
        if candidates.is_empty() {
            return pick(&mut self.rng);
        }
        let weights: Vec<u32> = candidates.iter().map(|e| e.weight).collect();
        let idx = self.rng.weighted_index(&weights);
        candidates[idx].to_owned()
    }

    /// Next UA, freshly chosen (for per-request rotation across many hosts).
    // Not an iterator: this is a deliberate rotation API, so the `next` name reads
    // naturally and renaming it would churn the crate's public surface.
    #[allow(clippy::should_implement_trait)]
    pub fn next(&mut self) -> UserAgent {
        self.pick_now()
    }

    /// The UA to use for `host`, chosen once and then kept stable for that host.
    /// This is the right call for session-based scraping: one identity per site.
    pub fn for_host(&mut self, host: &str) -> UserAgent {
        if let Some((_, ua)) = self.sticky.iter().find(|(h, _)| h == host) {
            return ua.clone();
        }
        let ua = self.pick_now();
        self.sticky.push((host.to_string(), ua.clone()));
        ua
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pool_entries_are_internally_consistent() {
        // Every UA string must mention its family's token and its version, so
        // the metadata can't silently drift from the string.
        for e in POOL {
            let s = e.string;
            match e.family {
                Firefox => assert!(s.contains("Firefox/"), "{s}"),
                Chrome => assert!(s.contains("Chrome/") && !s.contains("Edg/"), "{s}"),
                Edge => assert!(s.contains("Edg/"), "{s}"),
                Safari => assert!(s.contains("Safari/") && s.contains("Version/"), "{s}"),
            }
            assert!(
                s.contains(&e.major_version.to_string()),
                "version {} not in {s}",
                e.major_version
            );
            assert!(e.weight > 0, "zero weight: {s}");
        }
    }

    #[test]
    fn random_user_agent_is_deterministic() {
        assert_eq!(random_user_agent(123), random_user_agent(123));
    }

    #[test]
    fn family_filter_returns_that_family() {
        for seed in 0..20 {
            let ua = random_user_agent_for(seed, BrowserFamily::Firefox);
            assert_eq!(ua.family, BrowserFamily::Firefox);
            assert!(ua.string.contains("Firefox/"));
        }
    }

    #[test]
    fn rotator_is_sticky_per_host() {
        let mut r = UserAgentRotator::new(7);
        let a1 = r.for_host("example.com");
        let a2 = r.for_host("example.com");
        assert_eq!(a1, a2, "same host must get the same UA");
        // A different host may differ (not guaranteed, but the mapping is
        // independent); at minimum it must not panic and must be a pool member.
        let b = r.for_host("other.test");
        assert!(POOL.iter().any(|e| e.string == b.string));
    }

    #[test]
    fn rotator_family_restriction_holds() {
        let mut r = UserAgentRotator::new(1).with_family(BrowserFamily::Chrome);
        for _ in 0..10 {
            assert_eq!(r.next().family, BrowserFamily::Chrome);
        }
    }

    #[test]
    fn weighting_prefers_common_browsers() {
        // Over many draws, Chrome (highest aggregate weight) should dominate
        // Firefox. A soft check that the weighting is actually applied.
        let mut chrome = 0;
        let mut firefox = 0;
        for seed in 0..2000 {
            match random_user_agent(seed).family {
                BrowserFamily::Chrome => chrome += 1,
                BrowserFamily::Firefox => firefox += 1,
                _ => {}
            }
        }
        assert!(chrome > firefox, "chrome {chrome} vs firefox {firefox}");
    }
}
