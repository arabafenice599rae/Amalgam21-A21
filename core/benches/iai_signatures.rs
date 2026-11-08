// ============================================================================
// AMALGAM21 A21 — BENCHMARK IAI-CALLGRIND: FIRMA ML-DSA-65
// ----------------------------------------------------------------------------
// Conteggio ESATTO di istruzioni macchina tramite Valgrind/callgrind:
// immune dal rumore dei runner condivisi, complementare ai benchmark
// statistici Criterion. La generazione della chiave è inclusa
// deliberatamente nella misurazione (il suo costo è stabile e tracciato).
// Esecuzione (richiede valgrind):
//   cargo bench -p token-postquantum --bench iai_signatures
// ============================================================================

use iai_callgrind::{library_benchmark, library_benchmark_group, main};
use token_postquantum::Wallet;

fn seed(i: u64) -> [u8; 32] {
    let mut s = [0u8; 32];
    s[..8].copy_from_slice(&i.to_le_bytes());
    s
}

#[library_benchmark]
fn keygen_and_sign_128b() {
    let wallet = Wallet::from_seed(seed(1));
    let msg = [7u8; 128];
    let sig = wallet.sign(&msg, b"bench.amalgam21.sign");
    std::hint::black_box(sig);
}

library_benchmark_group!(
    name = iai_signatures;
    benchmarks = keygen_and_sign_128b
);

main!(library_benchmark_groups = iai_signatures);
