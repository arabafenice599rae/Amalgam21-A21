// ============================================================================
// AMALGAM21 A21 — TEST DI INTEGRAZIONE: TRANSAZIONI (T02)
// ----------------------------------------------------------------------------
// Percorso funzionale di Claim e Transfer: creazione conto, airdrop, nonce,
// fee, importi nulli, autoinvio e saldo insufficiente. Tutto tramite API
// pubblica del crate core.
// ============================================================================

use std::path::PathBuf;
use token_postquantum::{GenesisParams, Ledger, LedgerError, SignedTransaction, Wallet};

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
        domain: "integration-transactions.v1".into(),
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
    let base = std::env::temp_dir().join(format!("amg21-tx-{}-{}", name, std::process::id()));
    let data = base.join("data");
    let ext = base.join("ext");
    std::fs::create_dir_all(&data).unwrap();
    std::fs::create_dir_all(&ext).unwrap();
    (data, ext)
}

#[test]
fn claim_creates_account_with_airdrop_and_nonce() {
    let (data, ext) = dirs("claim");
    let node = Wallet::from_seed(seed(9_001));
    let creator = Wallet::from_seed(seed(9_002));
    let alice = Wallet::from_seed(seed(1));
    let mut l = Ledger::open(&data, &ext, params(), &node, &creator).unwrap();
    let chain = l.state.genesis.genesis_hash;
    assert_eq!(l.state.balance(&alice.address), 0);
    l.submit(&node, vec![SignedTransaction::claim(&alice, chain, 0)])
        .unwrap();
    let acct = l.state.accounts.get(&alice.address).expect("conto creato");
    assert!(acct.claimed);
    assert_eq!(acct.balance, 100);
    assert_eq!(l.state.nonce(&alice.address), 1);
    assert_eq!(l.state.airdrop_pool, 200);
}

#[test]
fn transfer_from_unclaimed_account_rejected() {
    let (data, ext) = dirs("unclaimed");
    let node = Wallet::from_seed(seed(9_001));
    let creator = Wallet::from_seed(seed(9_002));
    let alice = Wallet::from_seed(seed(2));
    let mut l = Ledger::open(&data, &ext, params(), &node, &creator).unwrap();
    let chain = l.state.genesis.genesis_hash;
    // Funding: Alice è un conto esistente NON reclamato.
    l.submit(
        &node,
        vec![SignedTransaction::transfer(
            &creator,
            chain,
            0,
            alice.address,
            100,
        )],
    )
    .unwrap();
    let before = l.state.accounts.clone();
    match l.submit(
        &node,
        vec![SignedTransaction::transfer(
            &alice,
            chain,
            0,
            creator.address,
            1,
        )],
    ) {
        Err(LedgerError::UnclaimedAccount(_)) => {}
        other => panic!(
            "attesa UnclaimedAccount, ottenuto {:?}",
            other.map(|_| ())
        ),
    }
    assert_eq!(l.state.accounts, before);
}

#[test]
fn zero_amount_and_self_transfer_rejected() {
    let (data, ext) = dirs("zero");
    let node = Wallet::from_seed(seed(9_001));
    let creator = Wallet::from_seed(seed(9_002));
    let alice = Wallet::from_seed(seed(3));
    let mut l = Ledger::open(&data, &ext, params(), &node, &creator).unwrap();
    let chain = l.state.genesis.genesis_hash;
    l.submit(&node, vec![SignedTransaction::claim(&alice, chain, 0)])
        .unwrap();
    match l.submit(
        &node,
        vec![SignedTransaction::transfer(
            &alice,
            chain,
            1,
            creator.address,
            0,
        )],
    ) {
        Err(LedgerError::ZeroAmount) => {}
        other => panic!("attesa ZeroAmount, ottenuto {:?}", other.map(|_| ())),
    }
    match l.submit(
        &node,
        vec![SignedTransaction::transfer(
            &alice,
            chain,
            1,
            alice.address,
            5,
        )],
    ) {
        Err(LedgerError::ZeroAmount) => {}
        other => panic!("attesa ZeroAmount (self), ottenuto {:?}", other.map(|_| ())),
    }
}

#[test]
fn insufficient_balance_rejected() {
    let (data, ext) = dirs("insufficient");
    let node = Wallet::from_seed(seed(9_001));
    let creator = Wallet::from_seed(seed(9_002));
    let alice = Wallet::from_seed(seed(4));
    let mut l = Ledger::open(&data, &ext, params(), &node, &creator).unwrap();
    let chain = l.state.genesis.genesis_hash;
    l.submit(&node, vec![SignedTransaction::claim(&alice, chain, 0)])
        .unwrap();
    // Saldo 100 (airdrop): importo 5000 + fee > saldo.
    match l.submit(
        &node,
        vec![SignedTransaction::transfer(
            &alice,
            chain,
            1,
            creator.address,
            5000,
        )],
    ) {
        Err(LedgerError::InsufficientBalance { .. }) => {}
        other => panic!(
            "attesa InsufficientBalance, ottenuto {:?}",
            other.map(|_| ())
        ),
    }
    assert_eq!(l.state.balance(&alice.address), 100);
}

#[test]
fn nonce_progression_and_reuse() {
    let (data, ext) = dirs("nonce");
    let node = Wallet::from_seed(seed(9_001));
    let creator = Wallet::from_seed(seed(9_002));
    let alice = Wallet::from_seed(seed(5));
    let mut l = Ledger::open(&data, &ext, params(), &node, &creator).unwrap();
    let chain = l.state.genesis.genesis_hash;
    l.submit(&node, vec![SignedTransaction::claim(&alice, chain, 0)])
        .unwrap();
    // Nonce 1 e 2 in sequenza: accettati.
    l.submit(
        &node,
        vec![SignedTransaction::transfer(
            &alice,
            chain,
            1,
            creator.address,
            5,
        )],
    )
    .unwrap();
    l.submit(
        &node,
        vec![SignedTransaction::transfer(
            &alice,
            chain,
            2,
            creator.address,
            5,
        )],
    )
    .unwrap();
    // Riuso del nonce 2: rifiutato.
    match l.submit(
        &node,
        vec![SignedTransaction::transfer(
            &alice,
            chain,
            2,
            creator.address,
            5,
        )],
    ) {
        Err(LedgerError::BadNonce { expected: 3, got: 2 }) => {}
        other => panic!("attesa BadNonce, ottenuto {:?}", other.map(|_| ())),
    }
    assert_eq!(l.state.nonce(&alice.address), 3);
    assert_eq!(l.state.height, 3);
}
