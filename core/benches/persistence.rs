// ============================================================================
// AMALGAM21 A21 — BENCHMARK: RIAPERTURA DEL LEDGER
// ----------------------------------------------------------------------------
// Tempo di riapertura (lettura, verifica catena di hash e firme, ricostruzione
// integrale dello stato) per un ledger di 25 blocchi. Esecuzione:
//     cargo bench -p token-postquantum --bench persistence
// ============================================================================

use criterion::{BatchSize, criterion_group, criterion_main, Criterion};
use token_postquantum::{GenesisParams, Ledger, SignedTransaction, Wallet};

fn seed(i: u64) -> [u8; 32] {
    let mut s = [0u8; 32];
    s[..8].copy_from_slice(&i.to_le_bytes());
    s
}

fn bench_params() -> GenesisParams {
    GenesisParams {
        token_name: "Bench".into(),
        symbol: "BNH".into(),
        total_supply: 1_000_000_000,
        domain: "bench.v1".into(),
        creator_allocation: 999_999_000,
        fee_pool: 0,
        fee: 10,
        cashback_bps: 0,
        airdrop_pool: 0,
        airdrop_per_wallet: 0,
        airdrop_max_wallets: 0,
    }
}

pub fn bench_reopen(c: &mut Criterion) {
    let run_id = std::process::id();
    let mut counter = 0u64;
    c.bench_function("reopen_25_blocks", |b| {
        b.iter_batched(
            || {
                // Setup: ledger fresco con 25 blocchi di transfer dal creator.
                counter += 1;
                let base = std::env::temp_dir().join(format!(
                    "amg21-bench-reopen-{}-{}-{}",
                    run_id, counter, std::process::id()
                ));
                let data = base.join("data");
                let ext = base.join("ext");
                std::fs::create_dir_all(&data).unwrap();
                std::fs::create_dir_all(&ext).unwrap();
                let node = Wallet::from_seed(seed(9_001));
                let creator = Wallet::from_seed(seed(9_002));
                let alice = Wallet::from_seed(seed(9_003));
                let mut l =
                    Ledger::open(&data, &ext, bench_params(), &node, &creator).unwrap();
                let chain = l.state.genesis.genesis_hash;
                l.submit(&node, vec![SignedTransaction::claim(&alice, chain, 0)])
                    .unwrap();
                for n in 0..24u64 {
                    l.submit(
                        &node,
                        vec![SignedTransaction::transfer(
                            &creator,
                            chain,
                            n,
                            alice.address,
                            1,
                        )],
                    )
                    .unwrap();
                }
                drop(l);
                (data, ext, node, creator)
            },
            |(data, ext, node, creator)| {
                let l = Ledger::open(&data, &ext, bench_params(), &node, &creator).unwrap();
                assert_eq!(l.state.height, 25);
                drop(l);
                let _ = std::fs::remove_dir_all(data.parent().unwrap());
            },
            BatchSize::PerIteration,
        )
    });
}

criterion_group! {
    name = benches;
    config = Criterion::default()
        .warm_up_time(std::time::Duration::from_secs(1))
        .sample_size(10);
    targets = bench_reopen
}
criterion_main!(benches);
