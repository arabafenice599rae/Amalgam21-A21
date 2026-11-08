// ============================================================================
// core/src/tests.rs — Test unitari (eseguire con: cargo test).
// ============================================================================

use super::*;

use borsh::BorshSerialize;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::PathBuf;

struct Fixture {
    data: PathBuf,
    ext: PathBuf,
    node: Wallet,
    creator: Wallet,
    params: GenesisParams,
}

fn fixture(name: &str) -> Fixture {
    let data = std::env::temp_dir().join(format!("amg1-{}-{}-data", name, std::process::id()));
    let ext = std::env::temp_dir().join(format!("amg1-{}-{}-ext", name, std::process::id()));
    let _ = fs::remove_dir_all(&data);
    let _ = fs::remove_dir_all(&ext);
    // Le directory esistono da subito: i test dei wallet scrivono file
    // in `data` senza aprire prima un Ledger.
    fs::create_dir_all(&data).unwrap();
    fs::create_dir_all(&ext).unwrap();
    Fixture {
        node: Wallet::from_seed(os_random::<SEED_SIZE>()),
        creator: Wallet::from_seed(os_random::<SEED_SIZE>()),
        params: GenesisParams {
            token_name: "Test".into(),
            symbol: "TST".into(),
            total_supply: 1_000_000,
            domain: "test.v1".into(),
            creator_allocation: 599_700,
            fee_pool: 400_000,
            fee: 10,
            cashback_bps: 9_000,
            airdrop_pool: 300, // 100 unità per 3 wallet
            airdrop_per_wallet: 100,
            airdrop_max_wallets: 3,
        },
        data,
        ext,
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.data);
        let _ = fs::remove_dir_all(&self.ext);
    }
}

#[test]
fn claim_creates_missing_account() {
    let f = fixture("claim-new");
    let carol = Wallet::from_seed(os_random::<SEED_SIZE>());
    let mut l = Ledger::open(&f.data, &f.ext, f.params.clone(), &f.node, &f.creator).unwrap();
    let chain = l.state.genesis.genesis_hash;
    // Carol non esiste: il Claim crea il conto e accredita l'airdrop
    // (100 unità) alla prima transizione unclaimed -> claimed.
    l.submit(&f.node, vec![SignedTransaction::claim(&carol, chain, 0)])
        .unwrap();
    assert_eq!(l.state.balance(&carol.address), 100);
    assert_eq!(l.state.nonce(&carol.address), 1);
    assert_eq!(l.state.airdrop_recipients, 1);
    // Creator paga carol; carol spende. Fee 10, cashback 9 dal pool.
    l.submit(
        &f.node,
        vec![SignedTransaction::transfer(
            &f.creator,
            chain,
            0,
            carol.address,
            500,
        )],
    )
    .unwrap();
    l.submit(
        &f.node,
        vec![SignedTransaction::transfer(
            &carol,
            chain,
            1,
            f.creator.address,
            100,
        )],
    )
    .unwrap();
    // Carol: 100 + 500 - (100 + 10 di fee) + 9 di cashback = 499.
    assert_eq!(l.state.balance(&carol.address), 499);
    // Creator: 599_700 - (500 + 10) + 9 + 100 ricevuti = 599_299.
    assert_eq!(l.state.balance(&f.creator.address), 599_299);
    // Sistema: due fee intere (10 + 10) = 20 unità.
    assert_eq!(l.state.balance(&address_of(&f.node.verification_key)), 20);
    // Un secondo claim della stessa chiave è valido ma consuma un nonce;
    // l'airdrop non è MAI concesso due volte allo stesso conto.
    assert!(l
        .submit(&f.node, vec![SignedTransaction::claim(&carol, chain, 2)])
        .is_ok());
    assert_eq!(l.state.balance(&carol.address), 499);
    assert_eq!(l.state.airdrop_recipients, 1);
    // Claim contraffatto: mallory allega la PROPRIA vk ma dichiara from =
    // carol. address_of(vk_mallory) != carol -> rifiutato.
    let mallory = Wallet::from_seed(os_random::<SEED_SIZE>());
    let mut forged = SignedTransaction::claim(&mallory, chain, 3);
    forged.core.from = carol.address;
    match l.submit(&f.node, vec![forged]) {
        Err(LedgerError::InvalidSignature) => {}
        other => panic!("atteso InvalidSignature, ottenuto {:?}", other),
    }
}

#[test]
fn transfer_from_unclaimed_rejected() {
    let f = fixture("unclaimed");
    let alice = Wallet::from_seed(os_random::<SEED_SIZE>());
    let mut l = Ledger::open(&f.data, &f.ext, f.params.clone(), &f.node, &f.creator).unwrap();
    let chain = l.state.genesis.genesis_hash;
    l.submit(
        &f.node,
        vec![SignedTransaction::transfer(
            &f.creator,
            chain,
            0,
            alice.address,
            100,
        )],
    )
    .unwrap();
    let bad = SignedTransaction::transfer(&alice, chain, 0, f.creator.address, 10);
    match l.submit(&f.node, vec![bad]) {
        Err(LedgerError::UnclaimedAccount(_)) => {}
        other => panic!("atteso UnclaimedAccount, ottenuto {:?}", other.map(|_| ())),
    }
}

#[test]
fn double_nonce_same_block_rejected() {
    let f = fixture("multinonce");
    let mut l = Ledger::open(&f.data, &f.ext, f.params.clone(), &f.node, &f.creator).unwrap();
    let chain = l.state.genesis.genesis_hash;
    let alice = Wallet::from_seed(os_random::<SEED_SIZE>());
    let a = SignedTransaction::transfer(&f.creator, chain, 0, alice.address, 1);
    let b = SignedTransaction::transfer(&f.creator, chain, 0, alice.address, 1);
    match l.submit(&f.node, vec![a, b]) {
        Err(LedgerError::BadNonce {
            expected: 1,
            got: 0,
        }) => {}
        other => panic!("atteso BadNonce, ottenuto {:?}", other),
    }
}

#[test]
fn replay_rejected() {
    let f = fixture("replay");
    let alice = Wallet::from_seed(os_random::<SEED_SIZE>());
    let mut l = Ledger::open(&f.data, &f.ext, f.params.clone(), &f.node, &f.creator).unwrap();
    let chain = l.state.genesis.genesis_hash;
    let tx = SignedTransaction::transfer(&f.creator, chain, 0, alice.address, 100);
    l.submit(&f.node, vec![tx.clone()]).unwrap();
    match l.submit(&f.node, vec![tx]) {
        Err(LedgerError::BadNonce { .. }) => {}
        other => panic!("atteso BadNonce, ottenuto {:?}", other),
    }
}

#[test]
fn config_mismatch_rejected() {
    let f = fixture("config");
    let mut l = Ledger::open(&f.data, &f.ext, f.params.clone(), &f.node, &f.creator).unwrap();
    let chain = l.state.genesis.genesis_hash;
    let alice = Wallet::from_seed(os_random::<SEED_SIZE>());
    l.submit(
        &f.node,
        vec![SignedTransaction::transfer(
            &f.creator,
            chain,
            0,
            alice.address,
            1,
        )],
    )
    .unwrap();
    drop(l);
    let mut wrong = f.params.clone();
    wrong.symbol = "FAKE".into();
    match Ledger::open(&f.data, &f.ext, wrong, &f.node, &f.creator) {
        Err(LedgerError::ConfigMismatch { .. }) => {}
        other => panic!("atteso ConfigMismatch, ottenuto {:?}", other.map(|_| ())),
    }
}

#[test]
fn tampered_log_rejected() {
    let f = fixture("tamper");
    let mut l = Ledger::open(&f.data, &f.ext, f.params.clone(), &f.node, &f.creator).unwrap();
    let chain = l.state.genesis.genesis_hash;
    let alice = Wallet::from_seed(os_random::<SEED_SIZE>());
    l.submit(
        &f.node,
        vec![SignedTransaction::transfer(
            &f.creator,
            chain,
            0,
            alice.address,
            1,
        )],
    )
    .unwrap();
    drop(l);
    let log = f.data.join("ledger.log");
    let mut raw = fs::read(&log).unwrap();
    let mid = raw.len() / 2;
    raw[mid] ^= 0xFF;
    fs::write(&log, &raw).unwrap();
    match Ledger::open(&f.data, &f.ext, f.params.clone(), &f.node, &f.creator) {
        Err(e) => match e {
            LedgerError::TamperDetected { .. } | LedgerError::Io(_) => {}
            other => panic!("attesa manomissione, ottenuto {:?}", other),
        },
        Ok(_) => panic!("log manomesso accettato"),
    }
}

#[test]
fn combined_rollback_rejected() {
    let f = fixture("rollback");
    let mut l = Ledger::open(&f.data, &f.ext, f.params.clone(), &f.node, &f.creator).unwrap();
    let chain = l.state.genesis.genesis_hash;
    let alice = Wallet::from_seed(os_random::<SEED_SIZE>());
    l.submit(
        &f.node,
        vec![SignedTransaction::transfer(
            &f.creator,
            chain,
            0,
            alice.address,
            1,
        )],
    )
    .unwrap();
    // Backup locale dopo il blocco 1.
    fs::copy(f.data.join("ledger.log"), f.data.join("ledger.log.bak")).unwrap();
    fs::copy(
        f.data.join("ledger.anchor"),
        f.data.join("ledger.anchor.bak"),
    )
    .unwrap();
    // Blocco 2.
    l.submit(
        &f.node,
        vec![SignedTransaction::transfer(
            &f.creator,
            chain,
            1,
            alice.address,
            1,
        )],
    )
    .unwrap();
    drop(l);
    // Ripristino di log E anchor locali a quota 1: il journal esterno,
    // rimasto a quota 2, deve far scattare il rollback.
    fs::copy(f.data.join("ledger.log.bak"), f.data.join("ledger.log")).unwrap();
    fs::copy(
        f.data.join("ledger.anchor.bak"),
        f.data.join("ledger.anchor"),
    )
    .unwrap();
    match Ledger::open(&f.data, &f.ext, f.params.clone(), &f.node, &f.creator) {
        Err(LedgerError::RollbackDetected { source, .. }) => {
            assert_eq!(source, "esterno (journal)");
        }
        other => panic!(
            "atteso RollbackDetected dal journal, ottenuto {:?}",
            other.map(|_| ())
        ),
    }
}

#[test]
fn airdrop_first_wallets_then_cap() {
    let f = fixture("airdrop");
    let mut l = Ledger::open(&f.data, &f.ext, f.params.clone(), &f.node, &f.creator).unwrap();
    let chain = l.state.genesis.genesis_hash;
    // I primi 3 wallet (airdrop_max_wallets) ricevono 100 unità ciascuno.
    for _ in 0..3 {
        let w = Wallet::from_seed(os_random::<SEED_SIZE>());
        l.submit(&f.node, vec![SignedTransaction::claim(&w, chain, 0)])
            .unwrap();
        assert_eq!(l.state.balance(&w.address), 100);
    }
    assert_eq!(l.state.airdrop_pool, 0);
    assert_eq!(l.state.airdrop_recipients, 3);
    // Il quarto wallet reclama ma NON riceve l'airdrop.
    let late = Wallet::from_seed(os_random::<SEED_SIZE>());
    l.submit(&f.node, vec![SignedTransaction::claim(&late, chain, 0)])
        .unwrap();
    assert_eq!(l.state.balance(&late.address), 0);
    assert_eq!(l.state.airdrop_recipients, 3);
}

#[test]
fn fee_routing_and_pool_exhaustion() {
    let f = fixture("fee-routing");
    // Pool cashback da 5 unità: MENO del cashback pieno (9) di una fee.
    let params = GenesisParams {
        token_name: "Test".into(),
        symbol: "TST".into(),
        total_supply: 10_000,
        domain: "test.v1".into(),
        creator_allocation: 9_995,
        fee_pool: 5,
        fee: 10,
        cashback_bps: 9_000,
        airdrop_pool: 0,
        airdrop_per_wallet: 0,
        airdrop_max_wallets: 0,
    };
    let mut l = Ledger::open(&f.data, &f.ext, params, &f.node, &f.creator).unwrap();
    let chain = l.state.genesis.genesis_hash;
    let system = address_of(&f.node.verification_key);
    let alice = Wallet::from_seed(os_random::<SEED_SIZE>());
    l.submit(&f.node, vec![SignedTransaction::claim(&alice, chain, 0)])
        .unwrap();
    assert_eq!(l.state.balance(&alice.address), 0); // nessun airdrop
                                                    // Fee 1: cashback pieno sarebbe 9, ma il pool ha solo 5: rimborsati
                                                    // 5; la fee intera (10) va comunque al sistema.
    l.submit(
        &f.node,
        vec![SignedTransaction::transfer(
            &f.creator,
            chain,
            0,
            alice.address,
            1_000,
        )],
    )
    .unwrap();
    assert_eq!(l.state.cashback_pool, 0);
    assert_eq!(l.state.balance(&f.creator.address), 9_995 - 1_010 + 5);
    assert_eq!(l.state.balance(&system), 10);
    assert_eq!(l.state.balance(&alice.address), 1_000);
    // Fee 2: pool esaurito -> nessun rimborso; il mittente sostiene
    // l'intera fee, accreditata al sistema.
    l.submit(
        &f.node,
        vec![SignedTransaction::transfer(
            &alice,
            chain,
            1,
            f.creator.address,
            100,
        )],
    )
    .unwrap();
    assert_eq!(l.state.balance(&alice.address), 1_000 - 110);
    assert_eq!(l.state.balance(&system), 20);
}

#[test]
fn genesis_hash_binds_identities_and_collision_rejected() {
    let f = fixture("identity");
    // Stessi parametri, chiave del creatore diversa: chain id DIVERSO.
    let other = Wallet::from_seed(os_random::<SEED_SIZE>());
    let h1 = genesis_identity_hash(
        &f.params,
        &f.node.verification_key,
        &f.creator.address,
        &f.creator.verification_key,
    );
    let h2 = genesis_identity_hash(
        &f.params,
        &f.node.verification_key,
        &other.address,
        &other.verification_key,
    );
    assert_ne!(h1, h2);
    // Collisione creatore/conto di sistema: rifiutata da check_identity_collision.
    let mut rec = GenesisRecord::signed(f.params.clone(), &f.node, &f.creator);
    rec.creator_address = address_of(&f.node.verification_key);
    match rec.check_identity_collision() {
        Err(LedgerError::ConfigMismatch { .. }) => {}
        other_err => panic!(
            "attesa ConfigMismatch, ottenuto {:?}",
            other_err.map(|_| ())
        ),
    }
}

#[test]
fn address_encoding_roundtrip_and_checksum() {
    let w = Wallet::from_seed(os_random::<SEED_SIZE>());
    let enc = encode_address(&w.address);
    assert_eq!(decode_address(&enc).unwrap(), w.address);
    // Un carattere alterato è rifiutato: base58 o checksum.
    let mut chars: Vec<char> = enc.chars().collect();
    let last = chars.len() - 1;
    chars[last] = if chars[last] == '2' { '3' } else { '2' };
    let tampered: String = chars.into_iter().collect();
    assert!(decode_address(&tampered).is_err());
    // Prefisso assente: rifiutato.
    assert!(decode_address(&enc[4..]).is_err());
}

#[test]
fn journal_rejects_bad_publish_and_repairs_torn_tail() {
    let f = fixture("journal-repair");
    let alice = Wallet::from_seed(os_random::<SEED_SIZE>());
    {
        let mut l = Ledger::open(&f.data, &f.ext, f.params.clone(), &f.node, &f.creator).unwrap();
        let chain = l.state.genesis.genesis_hash;
        l.submit(
            &f.node,
            vec![SignedTransaction::transfer(
                &f.creator,
                chain,
                0,
                alice.address,
                1,
            )],
        )
        .unwrap();
    }
    // L'anchor pubblicato dal ledger è la voce a quota 1 del journal.
    let af: AnchorFile = borsh_exact(&fs::read(f.data.join("ledger.anchor")).unwrap()).unwrap();
    let journal = AnchorJournal::new(f.ext.join("anchor-journal.log"));
    // CONTROLLO PREVENTIVO: stessa altezza con tip differente -> rifiuto.
    let mut bad_tip = af.payload.clone();
    bad_tip.tip_record_hash = [7u8; HASH_SIZE];
    assert!(journal.publish(&f.node, bad_tip).is_err());
    // Altezza inferiore -> rifiuto.
    let mut lower = af.payload.clone();
    lower.height = 0;
    assert!(journal.publish(&f.node, lower).is_err());
    // Idempotenza esatta: stessa altezza e stesso tip -> Ok(false).
    assert!(matches!(
        journal.publish(&f.node, af.payload.clone()),
        Ok(false)
    ));
    // Coda incompleta (crash simulato): la riapertura la tollera e la
    // publish successiva la TRONCA prima dell'append.
    {
        let mut jf = OpenOptions::new()
            .append(true)
            .open(f.ext.join("anchor-journal.log"))
            .unwrap();
        jf.write_all(&[0xAB, 0xCD, 0x00]).unwrap();
    }
    let mut l = Ledger::open(&f.data, &f.ext, f.params.clone(), &f.node, &f.creator).unwrap();
    let chain = l.state.genesis.genesis_hash;
    l.submit(
        &f.node,
        vec![SignedTransaction::transfer(
            &f.creator,
            chain,
            1,
            alice.address,
            1,
        )],
    )
    .unwrap();
    drop(l);
    // Il journal ripulito resta leggibile e coerente.
    let l = Ledger::open(&f.data, &f.ext, f.params.clone(), &f.node, &f.creator).unwrap();
    assert_eq!(l.state.height, 2);
}

#[test]
fn wallet_rejects_permissive_kdf_params() {
    let f = fixture("kdf-limits");
    let path = f.data.join("w.wallet");
    // Header contraffatto: il caricamento richiederebbe 256 MiB di RAM.
    #[derive(BorshSerialize)]
    struct FakeWalletFile<'a> {
        magic: &'a [u8; 8],
        version: u32,
        kdf_id: &'a str,
        kdf_m_kib: u32,
        kdf_t: u32,
        kdf_p: u32,
        salt: &'a [u8; 16],
        aead_id: &'a str,
        nonce: &'a [u8; 24],
        ciphertext: &'a [u8],
    }
    let file = FakeWalletFile {
        magic: WALLET_MAGIC,
        version: WALLET_VERSION,
        kdf_id: WALLET_KDF_ID,
        kdf_m_kib: 256 * 1024, // oltre MAX_KDF_M_KIB (128 MiB)
        kdf_t: 3,
        kdf_p: 4,
        salt: &[0u8; 16],
        aead_id: WALLET_AEAD_ID,
        nonce: &[0u8; 24],
        ciphertext: &[0u8; SEED_SIZE + 16],
    };
    fs::write(&path, borsh::to_vec(&file).unwrap()).unwrap();
    match Wallet::load_encrypted(&path, b"pass") {
        Err(msg) => assert!(
            msg.contains("limiti"),
            "atteso rifiuto per limiti, ottenuto: {}",
            msg
        ),
        Ok(_) => panic!("wallet con parametri KDF eccessivi accettato"),
    }
}

#[test]
fn journal_duplicate_only_at_tail() {
    let f = fixture("journal-dup");
    let alice = Wallet::from_seed(os_random::<SEED_SIZE>());
    let jpath = f.ext.join("anchor-journal.log");
    {
        let mut l = Ledger::open(&f.data, &f.ext, f.params.clone(), &f.node, &f.creator).unwrap();
        let chain = l.state.genesis.genesis_hash;
        l.submit(
            &f.node,
            vec![SignedTransaction::transfer(
                &f.creator,
                chain,
                0,
                alice.address,
                1,
            )],
        )
        .unwrap();
        l.submit(
            &f.node,
            vec![SignedTransaction::transfer(
                &f.creator,
                chain,
                1,
                alice.address,
                1,
            )],
        )
        .unwrap();
    }
    // Estrae le voci complete dal journal (header 12 byte + voci):
    // il genesis è ancorato alla quota 0, quindi e0=genesis, e1, e2.
    let raw = fs::read(&jpath).unwrap();
    let mut entries: Vec<Vec<u8>> = Vec::new();
    let mut pos = 12usize;
    while pos < raw.len() {
        let len = u32::from_le_bytes(raw[pos..pos + 4].try_into().unwrap()) as usize;
        entries.push(raw[pos..pos + 4 + len].to_vec());
        pos += 4 + len;
    }
    assert_eq!(entries.len(), 3);
    let gh = genesis_identity_hash(
        &f.params,
        &f.node.verification_key,
        &f.creator.address,
        &f.creator.verification_key,
    );
    let journal = AnchorJournal::new(jpath.clone());
    // Duplicato IN CODA (e0 + e1 + e2 + e2): tollerato.
    let mut tail_dup = raw[..12].to_vec();
    tail_dup.extend_from_slice(&entries[0]);
    tail_dup.extend_from_slice(&entries[1]);
    tail_dup.extend_from_slice(&entries[2]);
    tail_dup.extend_from_slice(&entries[2]);
    fs::write(&jpath, &tail_dup).unwrap();
    assert!(journal.read_last(&f.node.verification_key, &gh).is_ok());
    // Duplicato IN MEZZO (e0 + e1 + e1 + e2): errore bloccante.
    let mut mid_dup = raw[..12].to_vec();
    mid_dup.extend_from_slice(&entries[0]);
    mid_dup.extend_from_slice(&entries[1]);
    mid_dup.extend_from_slice(&entries[1]);
    mid_dup.extend_from_slice(&entries[2]);
    fs::write(&jpath, &mid_dup).unwrap();
    assert!(journal.read_last(&f.node.verification_key, &gh).is_err());
}

#[test]
fn empty_log_reinitialized_not_tamper() {
    let f = fixture("empty-log");
    // Log di 0 byte (crash tra creazione e prima scrittura), journal
    // assente: la prima apertura NON deve segnalarlo come manomissione.
    fs::create_dir_all(&f.data).unwrap();
    fs::create_dir_all(&f.ext).unwrap();
    fs::write(f.data.join("ledger.log"), b"").unwrap();
    let l = Ledger::open(&f.data, &f.ext, f.params.clone(), &f.node, &f.creator).unwrap();
    assert_eq!(l.state.height, 0);
    drop(l);
    // Riapertura normale: il log ora ha contenuto e la verifica completa
    // deve passare.
    let l = Ledger::open(&f.data, &f.ext, f.params.clone(), &f.node, &f.creator).unwrap();
    assert_eq!(l.state.height, 0);
}

#[test]
fn empty_log_with_journal_entries_blocked() {
    let f = fixture("empty-log-blocked");
    let alice = Wallet::from_seed(os_random::<SEED_SIZE>());
    {
        let mut l = Ledger::open(&f.data, &f.ext, f.params.clone(), &f.node, &f.creator).unwrap();
        let chain = l.state.genesis.genesis_hash;
        l.submit(
            &f.node,
            vec![SignedTransaction::transfer(
                &f.creator,
                chain,
                0,
                alice.address,
                1,
            )],
        )
        .unwrap();
    }
    // Il log viene azzerato MA il journal contiene già ancore: non è
    // un crash genuino. L'apertura deve essere bloccata.
    fs::write(f.data.join("ledger.log"), b"").unwrap();
    match Ledger::open(&f.data, &f.ext, f.params.clone(), &f.node, &f.creator) {
        Err(LedgerError::TamperDetected { .. }) => {}
        other => panic!("attesa TamperDetected, ottenuto {:?}", other.map(|_| ())),
    }
}

#[test]
fn wallet_roundtrip() {
    let f = fixture("wallet");
    let path = f.data.join("w.wallet");
    let w = Wallet::from_seed(os_random::<SEED_SIZE>());
    w.save_encrypted(&path, b"pass-forte-123").unwrap();
    let loaded = Wallet::load_encrypted(&path, b"pass-forte-123").unwrap();
    assert_eq!(loaded.address, w.address);
    assert!(Wallet::load_encrypted(&path, b"pass-errata").is_err());
}

#[test]
fn erc20_facade_semantics() {
    let f = fixture("erc20");
    let carol = Wallet::from_seed(os_random::<SEED_SIZE>());
    let mut l = Ledger::open(&f.data, &f.ext, f.params.clone(), &f.node, &f.creator).unwrap();
    // Parità di lettura con un token tradizionale: name, symbol,
    // decimals, totalSupply.
    assert_eq!(l.state.erc20_name(), "Test");
    assert_eq!(l.state.erc20_symbol(), "TST");
    assert_eq!(l.state.erc20_decimals(), 6);
    assert_eq!(l.state.erc20_total_supply(), f.params.total_supply);
    assert_eq!(l.state.erc20_total_supply(), 1_000_000);
    // balanceOf: indirizzo mai visto -> 0, come in ERC-20.
    assert_eq!(l.state.erc20_balance_of(&carol.address), 0);
    // La facciata coincide con la contabilità interna dopo un'operazione
    // (claim + airdrop: il pool si scarica sul saldo, la supply no).
    let chain = l.state.genesis.genesis_hash;
    l.submit(&f.node, vec![SignedTransaction::claim(&carol, chain, 0)])
        .unwrap();
    assert_eq!(
        l.state.erc20_balance_of(&carol.address),
        l.state.balance(&carol.address)
    );
    assert_eq!(l.state.erc20_balance_of(&carol.address), 100);
    assert_eq!(l.state.erc20_total_supply(), 1_000_000);
}

#[test]
fn forged_transfer_signature_rejected() {
    let f = fixture("forged-sig");
    let alice = Wallet::from_seed(os_random::<SEED_SIZE>());
    let mut l = Ledger::open(&f.data, &f.ext, f.params.clone(), &f.node, &f.creator).unwrap();
    let chain = l.state.genesis.genesis_hash;
    l.submit(&f.node, vec![SignedTransaction::claim(&alice, chain, 0)])
        .unwrap();
    // Asserzione automatica: una firma ML-DSA-65 contraffatta è rifiutata
    // e lo stato contabile NON cambia (undo log: byte-identico).
    let mut forged = SignedTransaction::transfer(&alice, chain, 1, f.creator.address, 100);
    forged.signature = vec![0u8; SIG_SIZE];
    match l.submit(&f.node, vec![forged]) {
        Err(LedgerError::InvalidSignature) => {}
        other => panic!("attesa InvalidSignature, ottenuto {:?}", other.map(|_| ())),
    }
    assert_eq!(l.state.balance(&alice.address), 100);
    assert_eq!(l.state.nonce(&alice.address), 1);
    assert_eq!(l.state.balance(&f.creator.address), 599_700);
}

#[test]
fn forged_transfer_after_claim_same_block_rejected() {
    let f = fixture("claim-then-forged");
    let alice = Wallet::from_seed(os_random::<SEED_SIZE>());
    let mut l = Ledger::open(&f.data, &f.ext, f.params.clone(), &f.node, &f.creator).unwrap();
    let chain = l.state.genesis.genesis_hash;
    // 1. Il creatore trasferisce fondi ad Alice: conto ESISTENTE ma NON
    //    ancora reclamato (vk azzerata).
    l.submit(
        &f.node,
        vec![SignedTransaction::transfer(
            &f.creator,
            chain,
            0,
            alice.address,
            100,
        )],
    )
    .unwrap();
    let before = l.state.clone();
    // 2. Nello STESSO blocco: Claim valido di Alice + Transfer con
    //    nonce 1 e firma AZZERATA (contraffatta). Senza la correzione,
    //    la pre-verifica rinvia il Transfer (mittente non reclamato a
    //    inizio blocco), il Claim registra la vk e il Transfer passa
    //    senza che nessuna firma sia mai stata verificata.
    let claim = SignedTransaction::claim(&alice, chain, 0);
    let mut forged = SignedTransaction::transfer(&alice, chain, 1, f.creator.address, 50);
    forged.signature = vec![0u8; SIG_SIZE];
    match l.submit(&f.node, vec![claim, forged]) {
        Err(LedgerError::InvalidSignature) => {}
        other => panic!("attesa InvalidSignature, ottenuto {:?}", other.map(|_| ())),
    }
    // 3. Il blocco è scartato per intero: lo stato resta byte-identico
    //    (undo log) e nessun fondo è movimentato.
    assert_eq!(l.state.accounts, before.accounts);
    assert_eq!(l.state.accounts_total, before.accounts_total);
    assert_eq!(l.state.height, before.height);
    assert_eq!(l.state.blocks.len(), before.blocks.len());
    assert_eq!(l.state.balance(&alice.address), 100);
    // 4. Controllo positivo: lo stesso blocco con firma VALIDA è
    //    accettato (il percorso Claim→Transfer legittimo non è rotto).
    let claim = SignedTransaction::claim(&alice, chain, 0);
    let ok = SignedTransaction::transfer(&alice, chain, 1, f.creator.address, 50);
    l.submit(&f.node, vec![claim, ok]).unwrap();
    // Alice: 100 (funding) + 100 (airdrop) - 50 - fee(10) + cashback(9).
    assert_eq!(l.state.nonce(&alice.address), 2);
    assert_eq!(
        l.state.balance(&alice.address),
        100 + f.params.airdrop_per_wallet - 50 - f.params.fee + f.params.cashback_of_fee()
    );
}

#[test]
fn apply_block_rollback_restores_state_byte_identical() {
    let f = fixture("rollback-state");
    let mut l = Ledger::open(&f.data, &f.ext, f.params.clone(), &f.node, &f.creator).unwrap();
    let chain = l.state.genesis.genesis_hash;
    let alice = Wallet::from_seed(os_random::<SEED_SIZE>());
    let bob = Wallet::from_seed(os_random::<SEED_SIZE>());
    l.submit(&f.node, vec![SignedTransaction::claim(&alice, chain, 0)])
        .unwrap();
    l.submit(&f.node, vec![SignedTransaction::claim(&bob, chain, 0)])
        .unwrap();
    // Stato di riferimento prima del tentativo fallito.
    let before = l.state.clone();
    let before_total = l.state.accounts_total;
    // Blocco con una tx valida seguita da una NON valida (nonce
    // saltato): l'intero blocco è rifiutato e lo stato deve tornare
    // IDENTICO, incluso accounts_total e la mappa conti.
    let good = SignedTransaction::transfer(&alice, chain, 1, bob.address, 10);
    let bad = SignedTransaction::transfer(&alice, chain, 5, bob.address, 10);
    match l.submit(&f.node, vec![good, bad]) {
        Err(LedgerError::BadNonce { .. }) => {}
        other => panic!("atteso BadNonce, ottenuto {:?}", other),
    }
    assert_eq!(l.state.accounts, before.accounts);
    assert_eq!(l.state.accounts_total, before_total);
    assert_eq!(l.state.height, before.height);
    assert_eq!(l.state.cashback_pool, before.cashback_pool);
    // Il blocco rifiutato non è nella storia.
    assert_eq!(l.state.blocks.len(), before.blocks.len());
}

// ---------------------------------------------------------------------------
// v0.13: checkpoint firmato, rotazione dei segmenti, indipendenza del journal
// ---------------------------------------------------------------------------

#[test]
fn checkpoint_rotation_and_reopen() {
    let f = fixture("ckpt-rotate");
    let alice = Wallet::from_seed(os_random::<SEED_SIZE>());
    {
        let mut l = Ledger::open(&f.data, &f.ext, f.params.clone(), &f.node, &f.creator).unwrap();
        let chain = l.state.genesis.genesis_hash;
        l.enable_checkpoints(2);
        // Blocco 1: sotto soglia, nessun checkpoint, nessuna rotazione.
        l.submit(
            &f.node,
            vec![SignedTransaction::transfer(
                &f.creator,
                chain,
                0,
                alice.address,
                1,
            )],
        )
        .unwrap();
        assert!(!f.data.join("ledger.ckpt").exists());
        // Blocco 2: checkpoint firmato + archiviazione del segmento.
        l.submit(
            &f.node,
            vec![SignedTransaction::transfer(
                &f.creator,
                chain,
                1,
                alice.address,
                1,
            )],
        )
        .unwrap();
        assert!(f.data.join("ledger.ckpt").exists());
        assert!(f.data.join("ledger.log.2").exists());
        // Blocco 3: nel NUOVO segmento (senza genesis).
        l.submit(
            &f.node,
            vec![SignedTransaction::transfer(
                &f.creator,
                chain,
                2,
                alice.address,
                1,
            )],
        )
        .unwrap();
        assert_eq!(l.state.height, 3);
        assert_eq!(l.state.balance(&alice.address), 3);
        assert_eq!(l.state.nonce(&f.creator.address), 3);
    }
    // Riapertura: replay PARZIALE dal checkpoint (base a quota 2) + replay
    // del solo blocco 3 del segmento ruotato.
    let mut l = Ledger::open(&f.data, &f.ext, f.params.clone(), &f.node, &f.creator).unwrap();
    assert_eq!(l.state.height, 3);
    assert_eq!(l.state.balance(&alice.address), 3);
    assert_eq!(l.state.nonce(&f.creator.address), 3);
    assert_eq!(l.state.accounts_total, l_recount(&l));
    // Il ledger resta pienamente operativo dopo il recovery, e la politica
    // di rotazione sopravvive come configurazione di runtime riapplicata.
    let chain = l.state.genesis.genesis_hash;
    l.enable_checkpoints(2);
    l.submit(
        &f.node,
        vec![SignedTransaction::transfer(
            &f.creator,
            chain,
            3,
            alice.address,
            1,
        )],
    )
    .unwrap();
    assert_eq!(l.state.height, 4);
    // Quota 4: nuova rotazione; il segmento attivo è VUOTO.
    drop(l);
    let l = Ledger::open(&f.data, &f.ext, f.params.clone(), &f.node, &f.creator).unwrap();
    assert_eq!(l.state.height, 4);
    assert_eq!(l.state.balance(&alice.address), 4);
}

/// Riconteggio completo della supply per il controllo incrociato dei test.
fn l_recount(l: &Ledger) -> u128 {
    let mut total: u128 = 0;
    for a in l.state.accounts.values() {
        total += a.balance as u128;
    }
    total
}

#[test]
fn checkpoint_tampered_rejected() {
    let f = fixture("ckpt-tamper");
    let alice = Wallet::from_seed(os_random::<SEED_SIZE>());
    {
        let mut l = Ledger::open(&f.data, &f.ext, f.params.clone(), &f.node, &f.creator).unwrap();
        let chain = l.state.genesis.genesis_hash;
        l.enable_checkpoints(2);
        l.submit(
            &f.node,
            vec![SignedTransaction::transfer(
                &f.creator,
                chain,
                0,
                alice.address,
                1,
            )],
        )
        .unwrap();
        l.submit(
            &f.node,
            vec![SignedTransaction::transfer(
                &f.creator,
                chain,
                1,
                alice.address,
                1,
            )],
        )
        .unwrap();
        // Blocco 3 nel segmento ruotato: checkpoint attivo a quota 2.
        l.submit(
            &f.node,
            vec![SignedTransaction::transfer(
                &f.creator,
                chain,
                2,
                alice.address,
                1,
            )],
        )
        .unwrap();
    }
    // Un byte del checkpoint alterato: la firma ML-DSA-65 non deve più
    // verificarsi (o il corpo non deve deserializzarsi): apertura bloccata.
    let ckpt = f.data.join("ledger.ckpt");
    let mut raw = fs::read(&ckpt).unwrap();
    let mid = raw.len() / 2;
    raw[mid] ^= 0xFF;
    fs::write(&ckpt, &raw).unwrap();
    match Ledger::open(&f.data, &f.ext, f.params.clone(), &f.node, &f.creator) {
        Err(LedgerError::InvalidSignature) | Err(LedgerError::TamperDetected { .. }) => {}
        other => panic!(
            "attesa InvalidSignature o TamperDetected, ottenuto {:?}",
            other.map(|_| ())
        ),
    }
}

#[test]
fn rollback_stale_log_blocked() {
    let f = fixture("ckpt-stale");
    let alice = Wallet::from_seed(os_random::<SEED_SIZE>());
    {
        let mut l = Ledger::open(&f.data, &f.ext, f.params.clone(), &f.node, &f.creator).unwrap();
        let chain = l.state.genesis.genesis_hash;
        // Blocco 1 e backup di log E anchor locali a quota 1.
        l.submit(
            &f.node,
            vec![SignedTransaction::transfer(
                &f.creator,
                chain,
                0,
                alice.address,
                1,
            )],
        )
        .unwrap();
        fs::copy(f.data.join("ledger.log"), f.data.join("ledger.log.bak1")).unwrap();
        fs::copy(
            f.data.join("ledger.anchor"),
            f.data.join("ledger.anchor.bak1"),
        )
        .unwrap();
        // Rotazione a quota 2 e un blocco nel segmento ruotato (quota 3).
        l.enable_checkpoints(2);
        l.submit(
            &f.node,
            vec![SignedTransaction::transfer(
                &f.creator,
                chain,
                1,
                alice.address,
                1,
            )],
        )
        .unwrap();
        l.submit(
            &f.node,
            vec![SignedTransaction::transfer(
                &f.creator,
                chain,
                2,
                alice.address,
                1,
            )],
        )
        .unwrap();
    }
    // Attacco: ripristino del segmento STALE di quota 1 con cancellazione
    // del checkpoint. Il log è pieno e valido, l'anchor ripristinato è
    // coerente con il log: SOLO il journal esterno (a quota 3) può
    // smascherare il rollback.
    let _ = fs::remove_file(f.data.join("ledger.ckpt"));
    fs::copy(f.data.join("ledger.log.bak1"), f.data.join("ledger.log")).unwrap();
    fs::copy(
        f.data.join("ledger.anchor.bak1"),
        f.data.join("ledger.anchor"),
    )
    .unwrap();
    match Ledger::open(&f.data, &f.ext, f.params.clone(), &f.node, &f.creator) {
        Err(LedgerError::RollbackDetected { source, .. }) => {
            assert_eq!(source, "esterno (journal)");
        }
        other => panic!(
            "atteso RollbackDetected dal journal, ottenuto {:?}",
            other.map(|_| ())
        ),
    }
}

#[test]
fn open_independent_rejects_same_device() {
    let f = fixture("independent");
    // data ed ext sotto la STESSA directory temporanea: stesso filesystem.
    // L'apertura STRICT deve rifiutare: journal e dati sullo stesso device
    // non danno alcuna indipendenza reale.
    match Ledger::open_independent(&f.data, &f.ext, f.params.clone(), &f.node, &f.creator) {
        Err(LedgerError::JournalNotIndependent { .. }) => {}
        other => panic!(
            "attesa JournalNotIndependent, ottenuto {:?}",
            other.map(|_| ())
        ),
    }
    // L'apertura classica ammette lo stesso layout: l'indipendenza è una
    // proprietà dichiarata del deployment, non imposta da open().
    let l = Ledger::open(&f.data, &f.ext, f.params.clone(), &f.node, &f.creator).unwrap();
    assert_eq!(l.state.height, 0);
}
