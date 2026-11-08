// ============================================================================
// AMALGAM21 A21 — TEST DI INTEGRAZIONE: SICUREZZA (T05)
// ----------------------------------------------------------------------------
// Scenari ostili eseguiti ESCLUSIVAMENTE tramite l'interfaccia pubblica del
// crate core (nessun accesso ai tipi privati): firme contraffatte, replay,
// nonce duplicati, overflow, limiti airdrop e manomissione del log.
// Ogni test che attende un rifiuto verifica anche che lo stato contabile
// NON sia mutato (semantica all-or-nothing dell'undo log).
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
        domain: "integration-security.v1".into(),
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
    let base = std::env::temp_dir().join(format!("amg21-sec-{}-{}", name, std::process::id()));
    let data = base.join("data");
    let ext = base.join("ext");
    std::fs::create_dir_all(&data).unwrap();
    std::fs::create_dir_all(&ext).unwrap();
    (data, ext)
}

fn open(name: &str) -> (PathBuf, PathBuf, Wallet, Wallet, Ledger) {
    let (data, ext) = dirs(name);
    let node = Wallet::from_seed(seed(9_001));
    let creator = Wallet::from_seed(seed(9_002));
    let ledger = Ledger::open(&data, &ext, params(), &node, &creator).unwrap();
    (data, ext, node, creator, ledger)
}

/// Claim → Transfer contraffatto nello stesso blocco (regressione della
/// criticità individuata nell'analisi di sicurezza della v0.12).
#[test]
fn claim_then_forged_transfer_same_block_rejected() {
    let (_, _, node, creator, mut l) = open("claim-forged");
    let alice = Wallet::from_seed(seed(1));
    let chain = l.state.genesis.genesis_hash;
    // Il creatore finanzia Alice: conto esistente NON reclamato.
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
    // Claim valido + Transfer con nonce 1 e firma AZZERATA nello stesso
    // blocco: la pre-verifica rinvia il Transfer (mittente non reclamato a
    // inizio blocco); senza la verifica differita, la firma contraffatta
    // passerebbe dopo che il Claim ha registrato la vk.
    let claim = SignedTransaction::claim(&alice, chain, 0);
    let mut forged = SignedTransaction::transfer(&alice, chain, 1, creator.address, 50);
    forged.signature = vec![0u8; token_postquantum::SIG_SIZE];
    match l.submit(&node, vec![claim, forged]) {
        Err(LedgerError::InvalidSignature) => {}
        other => panic!("attesa InvalidSignature, ottenuto {:?}", other.map(|_| ())),
    }
    assert_eq!(l.state.accounts, before);
    assert_eq!(l.state.balance(&alice.address), 100);
}

/// Due transazioni con lo stesso nonce nello stesso blocco: il blocco è
/// rifiutato per intero e lo stato è byte-identico.
#[test]
fn duplicate_nonce_in_same_block_rejected() {
    let (_, _, node, creator, mut l) = open("dup-nonce");
    let alice = Wallet::from_seed(seed(2));
    let chain = l.state.genesis.genesis_hash;
    l.submit(&node, vec![SignedTransaction::claim(&alice, chain, 0)])
        .unwrap();
    let before = l.state.accounts.clone();
    let a = SignedTransaction::transfer(&alice, chain, 1, creator.address, 5);
    let b = SignedTransaction::transfer(&alice, chain, 1, creator.address, 6);
    match l.submit(&node, vec![a, b]) {
        Err(LedgerError::BadNonce {
            expected: 2,
            got: 1,
        }) => {}
        other => panic!("attesa BadNonce, ottenuto {:?}", other.map(|_| ())),
    }
    assert_eq!(l.state.accounts, before);
}

/// Replay di una transazione già confermata: il nonce è avanzato, il replay
/// è rifiutato con BadNonce.
#[test]
fn replay_of_confirmed_transaction_rejected() {
    let (_, _, node, creator, mut l) = open("replay");
    let alice = Wallet::from_seed(seed(3));
    let chain = l.state.genesis.genesis_hash;
    l.submit(&node, vec![SignedTransaction::claim(&alice, chain, 0)])
        .unwrap();
    let tx = SignedTransaction::transfer(&alice, chain, 1, creator.address, 7);
    l.submit(&node, vec![tx.clone()]).unwrap();
    let before = l.state.accounts.clone();
    match l.submit(&node, vec![tx]) {
        Err(LedgerError::BadNonce { .. }) => {}
        other => panic!("attesa BadNonce, ottenuto {:?}", other.map(|_| ())),
    }
    assert_eq!(l.state.accounts, before);
}

/// Importo massimo u64: il calcolo di importo + fee va in overflow checked
/// e il blocco è rifiutato, senza alcuna mutazione né saturazione.
#[test]
fn max_amount_overflow_rejected() {
    let (_, _, node, creator, mut l) = open("overflow");
    let alice = Wallet::from_seed(seed(4));
    let chain = l.state.genesis.genesis_hash;
    l.submit(&node, vec![SignedTransaction::claim(&alice, chain, 0)])
        .unwrap();
    let before = l.state.accounts.clone();
    let tx = SignedTransaction::transfer(&alice, chain, 1, creator.address, u64::MAX);
    match l.submit(&node, vec![tx]) {
        Err(LedgerError::Overflow) => {}
        other => panic!("attesa Overflow, ottenuto {:?}", other.map(|_| ())),
    }
    assert_eq!(l.state.accounts, before);
}

/// Claim simultanei al limite dell'airdrop: con tetto a 3 beneficiari, il
/// quarto Claim è ancora VALIDO (il conto viene reclamato) ma non riceve
/// l'airdrop; il pool resta esatto e la supply è conservata.
#[test]
fn claims_at_airdrop_limit_boundary() {
    let (_, _, node, _creator, mut l) = open("airdrop-limit");
    let chain = l.state.genesis.genesis_hash;
    let wallets: Vec<Wallet> = (0..4u64)
        .map(|i| Wallet::from_seed(seed(100 + i)))
        .collect();
    for w in &wallets {
        l.submit(&node, vec![SignedTransaction::claim(w, chain, 0)])
            .unwrap();
    }
    assert_eq!(l.state.airdrop_recipients, 3);
    assert_eq!(l.state.airdrop_pool, 0);
    for w in &wallets {
        assert!(l.state.accounts.get(&w.address).unwrap().claimed);
    }
    for w in &wallets[..3] {
        assert_eq!(l.state.balance(&w.address), 100);
    }
    // Il quarto beneficio' NESSUN airdrop oltre il tetto.
    assert_eq!(l.state.balance(&wallets[3].address), 0);
}

/// Alterazione di un singolo byte del log: la riapertura deve rifiutare il
/// ledger come manomesso (verifica catena di hash record per record).
#[test]
fn single_byte_tamper_in_log_detected_on_reopen() {
    let (data, ext, node, creator, mut l) = open("tamper-byte");
    let alice = Wallet::from_seed(seed(5));
    let chain = l.state.genesis.genesis_hash;
    l.submit(&node, vec![SignedTransaction::claim(&alice, chain, 0)])
        .unwrap();
    l.submit(
        &node,
        vec![SignedTransaction::transfer(
            &creator,
            chain,
            0,
            alice.address,
            25,
        )],
    )
    .unwrap();
    drop(l);
    // Altera UN byte a metà del log, lontano dall'header (12 byte).
    let log = data.join("ledger.log");
    let mut raw = std::fs::read(&log).unwrap();
    assert!(raw.len() > 12);
    let mid = raw.len() / 2;
    raw[mid] = raw[mid].wrapping_add(1);
    std::fs::write(&log, &raw).unwrap();
    match Ledger::open(&data, &ext, params(), &node, &creator) {
        Err(LedgerError::TamperDetected { .. }) | Err(LedgerError::InvalidSignature) => {}
        Ok(_) => panic!("ledger manomesso riaperto senza errore"),
        other => panic!("attesa TamperDetected, ottenuto {:?}", other.map(|_| ())),
    }
}
