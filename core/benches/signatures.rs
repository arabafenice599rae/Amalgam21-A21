// ============================================================================
// AMALGAM21 A21 — BENCHMARK: FIRMI ML-DSA-65
// ----------------------------------------------------------------------------
// Latenza di firma (wallet.sign) sul messaggio canonico di una transazione.
// La latenza di VERIFICA è misurata indirettamente in benches/ledger.rs:
// il pipeline submit() esegue la pre-verifica parallela prima dell'apply.
// Esecuzione: cargo bench -p token-postquantum --bench signatures
// ============================================================================

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use token_postquantum::Wallet;

fn seed(i: u64) -> [u8; 32] {
    let mut s = [0u8; 32];
    s[..8].copy_from_slice(&i.to_le_bytes());
    s
}

pub fn bench_sign(c: &mut Criterion) {
    let wallet = Wallet::from_seed(seed(1));
    let msg = [7u8; 128];
    let ctx = b"bench.amalgam21.sign";
    c.bench_function("mldsa65_sign_128b", |b| {
        b.iter(|| {
            let sig = wallet.sign(black_box(&msg), black_box(ctx));
            black_box(sig);
        })
    });
}

criterion_group! {
    name = benches;
    config = Criterion::default().warm_up_time(std::time::Duration::from_secs(1));
    targets = bench_sign
}
criterion_main!(benches);
