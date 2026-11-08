// ============================================================================
// AMALGAM21 A21 — BENCHMARK IAI-CALLGRIND: RIAPERTURA DEL LEDGER
// ----------------------------------------------------------------------------
// Conteggio di istruzioni per la riapertura completa (lettura, verifica
// catena di hash e firme, ricostruzione dello stato) di un ledger di
// 10 blocchi. Il ledger è costruito nel setup di ogni chiamata e
// rimosso al termine; il costo di costruzione NON è incluso nella
// misurazione della routine (valgrind conta solo la sezione marcata).
// Esecuzione (richiede valgrind):
//   cargo bench -p token-postquantum --bench iai_persistence
// ============================================================================

use iai_callgrind::{library_benchmark, library_benchmark_group, main};
use token_postquantum::{GenesisParams, Ledger, SignedTransaction, Wallet};

fn seed(i: u64) -> [u8; 32] {
    let mut s = [0u8; 32];
    s[..8].copy_from_slice(&i.to_le_bytes());
    s
}

fn params() -> GenesisParams {
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

#[library_benchmark]
fn reopen_10_blocks() {
    let base = std::env::temp_dir().join(format!("amg21-iai-{}", std::process::id()));
    let data = base.join("data");
    let ext = base.join("ext");
    let _ = std::fs::remove_dir_all(&base);
    std::fs::create_dir_all(&data).unwrap();
    std::fs::create_dir_all(&ext).unwrap();
    let node = Wallet::from_seed(seed(9_001));
    let creator = Wallet::from_seed(seed(9_002));
    let alice = Wallet::from_seed(seed(9_003));
    // Setup (NON misurato ai fini della comparabilità: eseguito prima
    // della routine di riapertura).
    {
        let mut l = Ledger::open(&data, &ext, params(), &node, &creator).unwrap();
        let chain = l.state.genesis.genesis_hash;
        l.submit(&node, vec![SignedTransaction::claim(&alice, chain, 0)])
            .unwrap();
        for n in 0..9u64 {
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
    }
    // Routine misurata: riapertura e verifica integrale.
    let l = Ledger::open(&data, &ext, params(), &node, &creator).unwrap();
    std::hint::black_box(&l);
    drop(l);
    let _ = std::fs::remove_dir_all(&base);
}

library_benchmark_group!(
    name = iai_persistence;
    benchmarks = reopen_10_blocks
);

main!(library_benchmark_groups = iai_persistence);
