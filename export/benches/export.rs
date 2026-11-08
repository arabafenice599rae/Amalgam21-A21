// ============================================================================
// AMALGAM21 A21 — BENCHMARK: EXPORT (snapshot JSON + indice JSONL)
// ----------------------------------------------------------------------------
// Costo di produzione e verifica dei documenti esportati. Esecuzione:
//     cargo bench -p token-postquantum-export --bench export
// ============================================================================

use criterion::{criterion_group, criterion_main, Criterion};
use std::path::PathBuf;
use token_postquantum::{GenesisParams, Ledger, SignedTransaction, Wallet};
use token_postquantum_export::{
    block_index, state_snapshot, verify_block_index, verify_state_snapshot,
};

fn seed(i: u64) -> [u8; 32] {
    let mut s = [0u8; 32];
    s[..8].copy_from_slice(&i.to_le_bytes());
    s
}

fn params() -> GenesisParams {
    GenesisParams {
        token_name: "Test".into(),
        symbol: "TST".into(),
        total_supply: 1_000_000,
        domain: "bench-export.v1".into(),
        creator_allocation: 599_700,
        fee_pool: 400_000,
        fee: 10,
        cashback_bps: 9_000,
        airdrop_pool: 300,
        airdrop_per_wallet: 100,
        airdrop_max_wallets: 3,
    }
}

pub fn bench_export(c: &mut Criterion) {
    let base = PathBuf::from(std::env::temp_dir())
        .join(format!("amg21-bench-export-{}", std::process::id()));
    let data = base.join("data");
    let ext = base.join("ext");
    std::fs::create_dir_all(&data).unwrap();
    std::fs::create_dir_all(&ext).unwrap();
    let node = Wallet::from_seed(seed(9_001));
    let creator = Wallet::from_seed(seed(9_002));
    let mut l = Ledger::open(&data, &ext, params(), &node, &creator).unwrap();
    let chain = l.state.genesis.genesis_hash;
    let wallets: Vec<Wallet> = (0..3u64)
        .map(|i| Wallet::from_seed(seed(5_000 + i)))
        .collect();
    for w in &wallets {
        l.submit(&node, vec![SignedTransaction::claim(w, chain, 0)])
            .unwrap();
    }
    for n in 0..10u64 {
        l.submit(
            &node,
            vec![SignedTransaction::transfer(
                &creator,
                chain,
                n,
                wallets[(n as usize) % 3].address,
                5,
            )],
        )
        .unwrap();
    }

    c.bench_function("state_snapshot_14_blocks", |b| {
        b.iter(|| state_snapshot(&l.state))
    });
    c.bench_function("block_index_14_blocks", |b| {
        b.iter(|| block_index(&l.state))
    });
    let snap = state_snapshot(&l.state);
    c.bench_function("verify_state_snapshot", |b| {
        b.iter(|| verify_state_snapshot(&snap))
    });
    let idx = block_index(&l.state);
    c.bench_function("verify_block_index", |b| {
        b.iter(|| verify_block_index(&idx))
    });
}

criterion_group! {
    name = benches;
    config = Criterion::default().warm_up_time(std::time::Duration::from_secs(1));
    targets = bench_export
}
criterion_main!(benches);
