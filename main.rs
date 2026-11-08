// ============================================================================
// TOKEN DIGITALE PROPRIETARIO POST-QUANTUM — v0.12 — core/src/main.rs (demo)
// ----------------------------------------------------------------------------
// Dal v0.10 il prototipo è un workspace Cargo a due crate:
//   core/   = nucleo (lib.rs) + questa demo (main.rs), crate
//             token_postquantum — binario token-postquantum;
//   export/ = crate token-postquantum-export: snapshot JSON dei saldi e
//             indice JSONL dei blocchi per explorer e indexer esterni.
// Compilazione e verifica: `cargo build && cargo test` dalla root del
// workspace. Esecuzione interattiva: la passphrase dei wallet è richiesta
// con prompt senza eco (rpassword); la variabile d'ambiente AMG_PASSPHRASE
// è eliminata (era leggibile in /proc/<pid>/environ e nei log di crash).
// Nessun formato binario cambia: i dati delle versioni >= v0.8 restano validi.
// ============================================================================

use std::fs;
use std::path::Path;
use token_postquantum::*;
// ---------------------------------------------------------------------------
// Demo end-to-end (v0.12)
// ---------------------------------------------------------------------------
fn main() {
    println!("=== Token Post-Quantum ML-DSA-65 — Prototipo v0.12 ===\n");

    // PASSPHRASE CON PROMPT SENZA ECO (v0.12): niente variabili d'ambiente.
    let passphrase = match rpassword::prompt_password("Passphrase dei wallet: ") {
        Ok(p) if !p.is_empty() => p,
        _ => {
            eprintln!("Passphrase mancante o vuota: impossibile procedere.");
            std::process::exit(2);
        }
    };
    let passphrase = passphrase.as_bytes();

    let data_dir = Path::new("./ledger-data");
    // PLACEHOLDER documentato: endpoint indipendente in produzione (WORM/notarizzazione).
    let ext_dir = Path::new("./ledger-external");
    let keys_dir = Path::new("./keys");
    fs::create_dir_all(keys_dir).expect("creazione directory chiavi");
    // La directory delle chiavi è esplicitamente 0o700 (unix): i wallet
    // cifrati non devono essere leggibili ad altri utenti dell'host,
    // indipendentemente dall'umask.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(keys_dir, fs::Permissions::from_mode(0o700));
    }

    let node = load_or_create_wallet(&keys_dir.join("node.wallet"), "nodo", passphrase);
    let creator = load_or_create_wallet(&keys_dir.join("creator.wallet"), "creator", passphrase);
    let alice = load_or_create_wallet(&keys_dir.join("alice.wallet"), "alice", passphrase);
    let bob = load_or_create_wallet(&keys_dir.join("bob.wallet"), "bob", passphrase);
    let carol = load_or_create_wallet(&keys_dir.join("carol.wallet"), "carol", passphrase);

    let params = GenesisParams {
        token_name: "Amalgam21 Token".into(),
        symbol: "AMG".into(),
        // Supply: 100M token in unità da 1e-6.
        total_supply: 100_000_000 * UNITS_PER_TOKEN,
        domain: "com.amalgam21.genesis.v1".into(),
        // 5M al creatore; 45M cashback delle fee; 50M airdrop.
        creator_allocation: 5_000_000 * UNITS_PER_TOKEN,
        fee_pool: 45_000_000 * UNITS_PER_TOKEN,
        fee: FEE_FIXED_UNITS, // 0.00005 AMG fissi (50 unità da 1e-6)
        cashback_bps: 9_000, // 90% delle fee restituito al mittente
        airdrop_pool: 50_000_000 * UNITS_PER_TOKEN,
        airdrop_per_wallet: 250 * UNITS_PER_TOKEN, // 50M / 200000, senza resto
        airdrop_max_wallets: 200_000,
    };
    println!("Genesis hash (SHAKE256-512, vincolato a parametri e identità di nodo e creatore): {}",
        hex(&genesis_identity_hash(&params, &node.verification_key, &creator.address, &creator.verification_key)));
    println!("Politica monetaria: supply 100M; creatore 5M; fee fissa {} AMG (90% cashback, 10% costo netto al mittente); airdrop 250 ai primi 200000 wallet.\n", fmt_amount(FEE_FIXED_UNITS));

    let mut ledger = Ledger::open(data_dir, ext_dir, params.clone(), &node, &creator).expect("apertura ledger");
    let chain = ledger.state.genesis.genesis_hash;
    println!("Ledger aperto: altezza {}\n", ledger.state.height);

    // 1. CLAIM SU CONTO INESISTENTE + AIRDROP: carol non ha mai ricevuto
    //    nulla; il Claim crea il conto, lo vincola alla sua chiave e le
    //    accredita 250 token dall'airdrop.
    let claim_carol = SignedTransaction::claim(&carol, chain, 0);
    ledger.submit(&node, vec![claim_carol]).expect("claim su conto inesistente validato");
    println!("Carol ha reclamato un conto inesistente: saldo={} AMG (airdrop), nonce={}", fmt_amount(ledger.state.balance(&carol.address)), ledger.state.nonce(&carol.address));

    // 2. FEE FISSA E CASHBACK: il creatore paga 100 token + 0.00005 di fee;
    //    la fee intera è accreditata al conto di sistema (address derivato
    //    dalla chiave del nodo), mentre il 90% torna al mittente dal pool
    //    cashback: costo netto del mittente = 10% della fee.
    let system = address_of(&node.verification_key);
    let before = ledger.state.balance(&creator.address);
    let t1 = SignedTransaction::transfer(&creator, chain, ledger.state.nonce(&creator.address), alice.address, 100 * UNITS_PER_TOKEN);
    ledger.submit(&node, vec![t1]).expect("emissione validata");
    println!("Transfer con fee: creatore {} -> {} AMG, sistema={} AMG, fee addebitata={} AMG",
        fmt_amount(before), fmt_amount(ledger.state.balance(&creator.address)), fmt_amount(ledger.state.balance(&system)), fmt_amount(params.fee));

    // 3. Claim di alice (airdrop 250 anche su conto esistente ma NON
    //    reclamato) + trasferimento verso bob nello stesso blocco.
    let claim_alice = SignedTransaction::claim(&alice, chain, ledger.state.nonce(&alice.address));
    let t2 = SignedTransaction::transfer(&alice, chain, ledger.state.nonce(&alice.address) + 1, bob.address, 10 * UNITS_PER_TOKEN);
    ledger.submit(&node, vec![claim_alice, t2]).expect("claim + trasferimento validati");

    // Backup locale a quota 3 per la demo del rollback combinato.
    fs::copy(data_dir.join("ledger.log"), data_dir.join("ledger.log.bak")).expect("backup log");
    fs::copy(data_dir.join("ledger.anchor"), data_dir.join("ledger.anchor.bak")).expect("backup anchor");

    // 4. Spesa da conto non reclamato: rifiutata con UnclaimedAccount.
    let premature = SignedTransaction::transfer(&bob, chain, ledger.state.nonce(&bob.address), alice.address, 50);
    match ledger.submit(&node, vec![premature]) {
        Err(e) => println!("Spesa da conto non reclamato rifiutata: {}", e),
        Ok(()) => panic!("ERRORE: spesa accettata senza claim!"),
    }

    // 5. Claim di bob (airdrop) + spesa valida.
    let claim_bob = SignedTransaction::claim(&bob, chain, ledger.state.nonce(&bob.address));
    let t3 = SignedTransaction::transfer(&bob, chain, ledger.state.nonce(&bob.address) + 1, alice.address, 5 * UNITS_PER_TOKEN);
    ledger.submit(&node, vec![claim_bob, t3]).expect("claim bob + trasferimento validati");

    // 6. Creator paga carol (conto reclamato alla nascita via claim).
    let t4 = SignedTransaction::transfer(&creator, chain, ledger.state.nonce(&creator.address), carol.address, 20 * UNITS_PER_TOKEN);
    ledger.submit(&node, vec![t4]).expect("pagamento a carol validato");
    let t5 = SignedTransaction::transfer(&carol, chain, ledger.state.nonce(&carol.address), alice.address, 5 * UNITS_PER_TOKEN);
    ledger.submit(&node, vec![t5]).expect("spesa di carol validata");

    // 7. Nonce multipli nello stesso blocco.
    let n = ledger.state.nonce(&alice.address);
    let dup_a = SignedTransaction::transfer(&alice, chain, n, bob.address, 10);
    let dup_b = SignedTransaction::transfer(&alice, chain, n, bob.address, 10);
    match ledger.submit(&node, vec![dup_a, dup_b]) {
        Err(e) => println!("Doppio nonce nello stesso blocco rifiutato: {}", e),
        Ok(()) => panic!("ERRORE: doppio nonce accettato!"),
    }

    // 8. Replay e firma contraffatta.
    let replay = SignedTransaction::transfer(&alice, chain, 0, bob.address, 250);
    match ledger.submit(&node, vec![replay]) {
        Err(e) => println!("Replay rifiutato: {}", e),
        Ok(()) => panic!("ERRORE: replay accettato!"),
    }
    let mut forged = SignedTransaction::transfer(&bob, chain, ledger.state.nonce(&bob.address), alice.address, 100);
    forged.signature = vec![0u8; SIG_SIZE];
    match ledger.submit(&node, vec![forged]) {
        Err(e) => println!("Firma non valida rifiutata: {}", e),
        Ok(()) => panic!("ERRORE: firma contraffatta accettata!"),
    }

    println!("\nSaldi (AMG): creatore={}, sistema={}, alice={}, bob={}, carol={}",
        fmt_amount(ledger.state.balance(&creator.address)),
        fmt_amount(ledger.state.balance(&system)),
        fmt_amount(ledger.state.balance(&alice.address)),
        fmt_amount(ledger.state.balance(&bob.address)),
        fmt_amount(ledger.state.balance(&carol.address)));
    println!("Pool cashback residuo: {} AMG; pool airdrop residuo: {} AMG; wallet airdrop: {}/{}",
        fmt_amount(ledger.state.cashback_pool),
        fmt_amount(ledger.state.airdrop_pool),
        ledger.state.airdrop_recipients,
        params.airdrop_max_wallets);
    println!("Altezza catena: {}", ledger.state.height);
    drop(ledger);

    // 9. Ricaricamento con verifica completa (firme di ogni blocco incluse).
    match Ledger::open(data_dir, ext_dir, params.clone(), &node, &creator) {
        Ok(l) => println!("Ricaricamento riuscito: altezza {}", l.state.height),
        Err(e) => println!("Ricaricamento FALLITO: {}", e),
    }

    // 10. Config mismatch.
    let mut wrong = params.clone();
    wrong.symbol = "FAKE".into();
    match Ledger::open(data_dir, ext_dir, wrong, &node, &creator) {
        Err(e) => println!("Apertura con configurazione errata rifiutata: {}", e),
        Ok(_) => panic!("ERRORE: ledger diverso da quello richiesto è stato aperto!"),
    }

    // 11. Manomissione del log.
    let log_path = data_dir.join("ledger.log");
    let anchor_path = data_dir.join("ledger.anchor");
    let journal = AnchorJournal::new(ext_dir.join("anchor-journal.log"));
    let mut tampered = fs::read(&log_path).expect("lettura log");
    let mid = tampered.len() / 2;
    tampered[mid] ^= 0xFF;
    let tampered_path = data_dir.join("ledger.tampered");
    fs::write(&tampered_path, &tampered).expect("scrittura copia manomessa");
    match Ledger::read_and_verify_log(&tampered_path, &anchor_path, &journal) {
        Err(e) => println!("Manomissione rilevata: {}", e),
        Ok(_) => panic!("ERRORE: file manomesso accettato!"),
    }

    // 12. Rollback combinato: log E anchor locali a quota precedente; il
    //     journal esterno, più avanti, deve rilevarlo.
    fs::copy(data_dir.join("ledger.log.bak"), &log_path).expect("ripristino log");
    fs::copy(data_dir.join("ledger.anchor.bak"), &anchor_path).expect("ripristino anchor");
    match Ledger::read_and_verify_log(&log_path, &anchor_path, &journal) {
        Err(e) => println!("Rollback combinato rilevato: {}", e),
        Ok(_) => panic!("ERRORE: rollback combinato accettato!"),
    }

    println!("\nCancellare ./ledger-data, ./ledger-external e ./keys per rieseguire la demo.");
    println!("Limitazione: il journal è indipendente solo se l'endpoint lo è (WORM/notarizzazione/timestamping).");
}

fn load_or_create_wallet(path: &Path, label: &str, passphrase: &[u8]) -> Wallet {
    if path.exists() {
        Wallet::load_encrypted(path, passphrase).expect("apertura portafoglio")
    } else {
        let w = Wallet::from_seed(os_random::<SEED_SIZE>());
        w.save_encrypted(path, passphrase).expect("salvataggio portafoglio");
        println!("Portafoglio '{}' creato (seed indipendente, cifrato): address = {}", label, encode_address(&w.address));
        w
    }
}
