// ============================================================================
// AMALGAM21 A21 — BENCHMARK: PIPELINE DI BLOCCO
// ----------------------------------------------------------------------------
// Misura il pipeline COMPLETO di un blocco da K transfer: firma ML-DSA-65
// delle K transazioni, pre-verifica parallela, apply con undo log e
// scrittura del log firmato. Esecuzione:
//     cargo bench -p token-postquantum --bench ledger
// ============================================================================

use criterion::{criterion_group, criterion_main, Criterion};
use std::path::PathBuf;
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

fn dirs(name: &str) -> (PathBuf, PathBuf) {
    let base = std::env::temp_dir().join(format!("amg21-bench-{}-{}", name, std::process::id()));
    let data = base.join("data");
    let ext = base.join("ext");
    std::fs::create_dir_all(&data).unwrap();
    std::fs::create_dir_all(&ext).unwrap();
    (data, ext)
}

pub fn bench_block_pipeline(c: &mut Criterion) {
    let (data, ext) = dirs("pipeline");
    let node = Wallet::from_seed(seed(9_001));
    let creator = Wallet::from_seed(seed(9_002));
    let mut l = Ledger::open(&data, &ext, bench_params(), &node, &creator).unwrap();
    let chain = l.state.genesis.genesis_hash;
    // 8 wallet reclamati e finanziati, per alternare mittenti.
    let wallets: Vec<Wallet> = (0..8u64)
        .map(|i| Wallet::from_seed(seed(7_000 + i)))
        .collect();
    l.submit(
        &node,
        wallets
            .iter()
            .map(|w| SignedTransaction::claim(w, chain, 0))
            .collect(),
    )
    .unwrap();
    let mut funding = Vec::new();
    for (i, w) in wallets.iter().enumerate() {
        funding.push(SignedTransaction::transfer(
            &creator, chain, i as u64, w.address, 10_000_000,
        ));
    }
    l.submit(&node, funding).unwrap();
    let mut nonces = vec![1u64; wallets.len()];

    c.bench_function("block_pipeline_8_transfers", |b| {
        b.iter(|| {
            let mut txs = Vec::with_capacity(8);
            for t in 0..8 {
                let s = t % wallets.len();
                let to = wallets[(s + 1) % wallets.len()].address;
                txs.push(SignedTransaction::transfer(
                    &wallets[s],
                    chain,
                    nonces[s],
                    to,
                    1,
                ));
                nonces[s] += 1;
            }
            l.submit(&node, txs).unwrap();
        })
    });
}

criterion_group! {
    name = benches;
    config = Criterion::default().warm_up_time(std::time::Duration::from_secs(1));
    targets = bench_block_pipeline
}
criterion_main!(benches);
