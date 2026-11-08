// ============================================================================
// AMALGAM21 A21 — TEST DI INTEGRAZIONE: PERSISTENZA E RECUPERO (T04)
// ----------------------------------------------------------------------------
// Riavvio, ricostruzione integrale dello stato dal log firmato e presenza
// dei file di persistenza (log, anchor, journal). Nessuna simulazione di
// crash con kill -9 in CI: la scrittura atomica (tmp + rename) del core
// rende ogni interruzione equivalente a "nessun blocco parziale".
// ============================================================================

use std::path::PathBuf;
use token_postquantum::{GenesisParams, Ledger, SignedTransaction, Wallet};

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
        domain: "integration-persistence.v1".into(),
        creator_allocation: 599_700,
        fee_pool: 400_000,
        fee: 10,
        cashback_bps: 9_000,
        airdrop_pool: 300,
        airdrop_per_wallet: 100,
        airdrop_max_wallets: 3,
    }
}

fn dirs(name: &str) -> (PathBuf, PathBuf) {
    let base = std::env::temp_dir().join(format!("amg21-per-{}-{}", name, std::process::id()));
    let data = base.join("data");
    let ext = base.join("ext");
    std::fs::create_dir_all(&data).unwrap();
    std::fs::create_dir_all(&ext).unwrap();
    (data, ext)
}

/// Riapertura dopo più blocchi: lo stato è ricostruito INTEGRALMENTE dal
/// log firmato e coincide campo per campo con lo stato pre-chiusura.
#[test]
fn reopen_rebuilds_full_state() {
    let (data, ext) = dirs("reopen");
    let node = Wallet::from_seed(seed(9_001));
    let creator = Wallet::from_seed(seed(9_002));
    let alice = Wallet::from_seed(seed(1));
    let bob = Wallet::from_seed(seed(2));
    let (height, balances, nonces, accounts_total) = {
        let mut l = Ledger::open(&data, &ext, params(), &node, &creator).unwrap();
        let chain = l.state.genesis.genesis_hash;
        l.submit(&node, vec![SignedTransaction::claim(&alice, chain, 0)])
            .unwrap();
        l.submit(&node, vec![SignedTransaction::claim(&bob, chain, 0)])
            .unwrap();
        l.submit(
            &node,
            vec![SignedTransaction::transfer(
                &creator,
                chain,
                0,
                alice.address,
                250,
            )],
        )
        .unwrap();
        l.submit(
            &node,
            vec![SignedTransaction::transfer(
                &alice,
                chain,
                1,
                bob.address,
                40,
            )],
        )
        .unwrap();
        let b = vec![
            (creator.address, l.state.balance(&creator.address)),
            (alice.address, l.state.balance(&alice.address)),
            (bob.address, l.state.balance(&bob.address)),
        ];
        let n = vec![
            (alice.address, l.state.nonce(&alice.address)),
            (bob.address, l.state.nonce(&bob.address)),
        ];
        (l.state.height, b, n, l.state.accounts_total)
    };
    let l2 = Ledger::open(&data, &ext, params(), &node, &creator).unwrap();
    assert_eq!(l2.state.height, height);
    assert_eq!(l2.state.accounts_total, accounts_total);
    for (addr, bal) in &balances {
        assert_eq!(&l2.state.balance(addr), bal);
    }
    for (addr, n) in &nonces {
        assert_eq!(&l2.state.nonce(addr), n);
    }
    // I pool sono ricostruiti con esattezza (airdrop: 2 claim da 100).
    assert_eq!(l2.state.airdrop_pool, 100);
    assert_eq!(l2.state.airdrop_recipients, 2);
    // La facciata ERC-20-like è coerente dopo la ricostruzione.
    assert_eq!(l2.state.erc20_total_supply(), 1_000_000);
    assert_eq!(l2.state.erc20_balance_of(&bob.address), 100 + 40);
}

/// I file di persistenza esistono dopo la scrittura di blocchi: log firmato
/// in data/, anchor e journal in ext/ (endpoint esterno).
#[test]
fn persistence_files_present_after_blocks() {
    let (data, ext) = dirs("files");
    let node = Wallet::from_seed(seed(9_001));
    let creator = Wallet::from_seed(seed(9_002));
    let alice = Wallet::from_seed(seed(3));
    let mut l = Ledger::open(&data, &ext, params(), &node, &creator).unwrap();
    let chain = l.state.genesis.genesis_hash;
    l.submit(&node, vec![SignedTransaction::claim(&alice, chain, 0)])
        .unwrap();
    drop(l);
    let log = std::fs::read(data.join("ledger.log")).unwrap();
    // Header: magic (8) + versione (4), poi il genesis e i blocchi.
    assert!(log.len() > 12);
    let journal = std::fs::read(ext.join("anchor-journal.log")).unwrap();
    assert!(!journal.is_empty());
}
