//! S8: the seeded generator the walks and fuzzers share (a plain LCG, so a failing seed replays).

pub(super) struct Rng(pub u64);

impl Rng {
    pub fn below(&mut self, n: usize) -> usize {
        self.0 = self
            .0
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        usize::try_from((self.0 >> 33) % n as u64).unwrap()
    }

    pub fn int(&mut self, lo: i64, hi: i64) -> i64 {
        lo + i64::try_from(self.below(usize::try_from(hi - lo + 1).unwrap())).unwrap()
    }
}

/// The seeds to run: `NEG_SEED` alone when it is set, else `default`.
pub(super) fn seeds(default: &[u64]) -> Vec<u64> {
    match std::env::var("NEG_SEED").ok().and_then(|s| s.parse().ok()) {
        Some(s) => vec![s],
        None => default.to_vec(),
    }
}
