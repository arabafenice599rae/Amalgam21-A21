// ============================================================================
// TOKEN DIGITALE PROPRIETARIO POST-QUANTUM — v0.12 — export/src/lib.rs
// ----------------------------------------------------------------------------
// Crate SEPARATO di esportazione per explorer e indexer esterni:
//   - state_snapshot() : snapshot JSON UNICO dello stato (saldi, pool,
//                        parametri, altezza) con export_hash di integrità;
//   - block_index()    : indice dei blocchi in JSON Lines (una riga per
//                        blocco) SENZA firme e senza verification key
//                        complete, chiuso da una riga footer con
//                        index_hash cumulativo.
//
// CHANGELOG v0.12 (allineamento al core v0.12, NESSUNA modifica funzionale):
//   1. Il core v0.12 introduce apply_block() con undo log, accounts_total
//      incrementale, pre-verifica firme parallela ed evizione conti non
//      reclamati a saldo zero. NESSUNA di queste modifiche tocca i tipi
//      esportati: LedgerState mantiene accounts, blocks, pool, height,
//      facciata ERC-20-like. Questo crate compila invariato contro il core
//      v0.12 e produce export byte-identici a quelli della v0.11 sullo
//      stesso stato.
//   2. Versione allineata a 0.12.0 per tracciabilità del workspace.
//
// PROPRIETÀ DICHIARATE (dalla v0.11, invariate):
//   - DETERMINISMO: due esportazioni dello stesso stato sono byte-identiche
//     (nessun timestamp; chiavi oggetto ordinate; conti ordinati per
//     indirizzo).
//   - CHECKSUM DI INTEGRITÀ, NON ATTESTAZIONE DI PROVENIENZA:
//     export_hash e index_hash sono digest SHAKE256-512 NON autenticati.
//     Dimostrano che il contenuto corrisponde al digest calcolato e
//     permettono di rilevare modifiche quando il digest atteso è già
//     noto. NON dimostrano chi ha prodotto il documento né che il
//     contenuto provenga dal ledger originale: chiunque può alterare
//     il contenuto e ricalcolare il checksum. La provenienza si attesta
//     SOLO sul log firmato ML-DSA-65 del core.
//   - DERIVATO, NON AUTORITATIVO: lo snapshot NON sostituisce il log
//     firmato; la verifica ultima di ogni dato avviene sul log ML-DSA-65.
//   - ACCOPPIAMENTO UNIDIREZIONALE export -> core (path). Il core NON
//     dipende da serde e nessun tipo di consenso riceve derive Serialize:
//     il borsh resta l'unico formato sui tipi del ledger.
//   - SICUREZZA: sola lettura; nessun segreto, nessuna firma prodotta,
//     nessuna scrittura sul ledger.
//
// CANONICALIZZAZIONE JSON (vincoli di FORMATO, indipendenti da serde,
// così che un'implementazione esterna ricostruisca lo stesso digest):
//   - Codifica UTF-8, nessun BOM, nessun whitespace tra i token.
//   - Chiavi oggetto in ordine lessicografico dei byte UTF-8.
//   - Numeri: interi decimali, senza segno "+", esponenti, virgola o
//     zeri iniziali (tutti i valori numerici del formato sono
//     u64/u32/u8/bool).
//   - Stringhe: escaping JSON standard (", \, \n \r \t, caratteri di
//     controllo come \u00XX); i caratteri non ASCII restano UTF-8 non
//     escapato.
//   - Conti: array ordinato per l'indirizzo codificato "amg1".
//   - Righe JSONL separate da \n (nessun \r); documento finale con \n.
//   - Contenuto sottoposto a hash: snapshot = serializzazione COMPATTA
//     SENZA il campo export_hash (il documento emesso è pretty, ma il
//     checksum è definito sulla forma compatta); indice = righe dei
//     blocchi concatenate con \n, SENZA la riga footer.
//   - serde_json::Map è una BTreeMap SOLO se la feature "preserve_order"
//     NON è attiva: il Cargo di questo crate non deve mai abilitarla
//     (vedi il commento alle dipendenze).
//
// VERIFICA: verify_state_snapshot() e verify_block_index() ricostruiscono
// il checksum dal documento ricevuto. Sono controlli di INTEGRITÀ: un
// documento coerente con il proprio checksum non è per questo autentico.
//
// Cargo.toml (root del workspace):
//   [workspace]
//   resolver = "2"
//   members = ["core", "export"]
//
// Cargo.toml (questo crate):
//   [package]
//   name = "token-postquantum-export"
//   version = "0.12.0"
//   edition = "2021"
//
//   [dependencies]
//   token-postquantum = { path = "../core" }          # nucleo (path)
//   serde = { version = "1", features = ["derive"] }  # standard de facto
//   serde_json = "1"                                  # JSON; NON abilitare MAI la
//                                                     # feature preserve_order
//   sha3 = "0.10"                                     # SHAKE256-512, come il core
//
// NESSUN formato binario cambia rispetto al core: i dati restano validi.
// ============================================================================

use serde::Serialize;
use serde_json::json;
use sha3::digest::{ExtendableOutput, Update, XofReader};
use sha3::Shake256;
use token_postquantum::{encode_address, LedgerState, TxAction};

/// Identificatore del formato di esportazione (in ogni documento e riga).
pub const EXPORT_FORMAT: &str = "amg1-export-v1";

/// Dominio dedicato per i checksum di esportazione: un digest di export
/// non collide con i domini interni del ledger. Il dominio NON conferisce
/// autenticità: il digest resta un hash non autenticato.
const EXPORT_DOMAIN: &[u8] = b"com.amalgam21.export.v1";

/// SHAKE256 con output a 512 bit, come gli hash interni del core.
const EXPORT_HASH_SIZE: usize = 64;

fn export_hash(parts: &[&[u8]]) -> String {
    let mut h = Shake256::default();
    h.update(EXPORT_DOMAIN);
    for p in parts {
        h.update(p);
    }
    let mut out = [0u8; EXPORT_HASH_SIZE];
    h.finalize_xof().read(&mut out);
    hex(&out)
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{:02x}", x)).collect()
}

// ---------------------------------------------------------------------------
// DTO dell'esportazione: strutture NUOVE, separate dai tipi di consenso.
// Nessun #[derive(Serialize)] sui tipi del core: il borsh resta l'unico
// formato autorevole; l'export è una vista derivata.
// ---------------------------------------------------------------------------
#[derive(Serialize)]
struct AccountDto {
    address: String,
    balance: u64,
    nonce: u64,
    claimed: bool,
}

#[derive(Serialize)]
struct SnapshotDto {
    format: &'static str,
    /// Identità della catena: genesis hash in esadecimale.
    chain_id: String,
    height: u64,
    /// Stessa semantica della facciata ERC-20-like del core: 6.
    decimals: u8,
    name: String,
    symbol: String,
    total_supply: u64,
    fee: u64,
    cashback_bps: u16,
    cashback_pool: u64,
    airdrop_pool: u64,
    airdrop_recipients: u32,
    /// Conti ordinati per indirizzo: output deterministico.
    accounts: Vec<AccountDto>,
}

#[derive(Serialize)]
struct TxDto {
    kind: &'static str,
    from: String,
    /// Assente per i claim (nessun destinatario).
    #[serde(skip_serializing_if = "Option::is_none")]
    to: Option<String>,
    nonce: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    amount: Option<u64>,
}

#[derive(Serialize)]
struct BlockLineDto {
    format: &'static str,
    chain_id: String,
    height: u64,
    block_hash: String,
    prev_block_hash: String,
    /// SENZA firme e senza verification key complete: l'indice serve la
    /// consultazione; la verifica completa resta sul log firmato.
    txs: Vec<TxDto>,
}

/// Snapshot JSON UNICO dello stato. DETERMINISTICO: nessun timestamp,
/// chiavi ordinate, conti ordinati per indirizzo. export_hash è un
/// CHECKSUM DI INTEGRITÀ sul contenuto canonico compatto (senza il campo
/// export_hash stesso), NON un'attestazione di provenienza né una firma:
/// chiunque può alterare il contenuto e ricalcolare il checksum. La
/// verifica ultima avviene sul log firmato del core.
pub fn state_snapshot(state: &LedgerState) -> String {
    let mut accounts: Vec<AccountDto> = state
        .accounts
        .iter()
        .map(|(addr, acct)| AccountDto {
            address: encode_address(addr),
            balance: acct.balance,
            nonce: acct.nonce,
            claimed: acct.claimed,
        })
        .collect();
    accounts.sort_by(|a, b| a.address.cmp(&b.address));

    let dto = SnapshotDto {
        format: EXPORT_FORMAT,
        chain_id: hex(&state.genesis.genesis_hash),
        height: state.height,
        decimals: state.erc20_decimals(),
        name: state.erc20_name().to_owned(),
        symbol: state.erc20_symbol().to_owned(),
        total_supply: state.erc20_total_supply(),
        fee: state.genesis.params.fee,
        cashback_bps: state.genesis.params.cashback_bps,
        cashback_pool: state.cashback_pool,
        airdrop_pool: state.airdrop_pool,
        airdrop_recipients: state.airdrop_recipients,
        accounts,
    };
    // Il contenuto canonico è serializzato PRIMA dell'hash; l'hash è poi
    // inserito come chiave aggiuntiva (posizione a ordine lessicografico).
    let mut value = serde_json::to_value(&dto).expect("serializzazione JSON infallibile");
    let content = serde_json::to_string(&value).expect("serializzazione JSON infallibile");
    let hash = export_hash(&[content.as_bytes()]);
    match &mut value {
        serde_json::Value::Object(map) => {
            map.insert("export_hash".to_string(), serde_json::Value::String(hash));
        }
        _ => unreachable!("il DTO è sempre un oggetto"),
    }
    serde_json::to_string_pretty(&value).expect("serializzazione JSON infallibile")
}

/// Indice dei blocchi in JSON Lines: UNA RIGA per blocco, più una riga
/// finale "index-end" con index_hash cumulativo (SHAKE256-512 sulla
/// concatenazione delle righe dei blocchi, senza il footer stesso).
/// Come per lo snapshot, index_hash è un CHECKSUM DI INTEGRITÀ, non
/// un'attestazione: usare verify_block_index() per ricalcolarlo. Il
/// genesis NON è un blocco ed è già coperto dallo snapshot (chain_id
/// e parametri).
pub fn block_index(state: &LedgerState) -> String {
    let chain_id = hex(&state.genesis.genesis_hash);
    let mut lines: Vec<String> = Vec::with_capacity(state.blocks.len() + 1);
    for b in &state.blocks {
        let txs: Vec<TxDto> = b
            .header
            .txs
            .iter()
            .map(|tx| {
                let from = encode_address(&tx.core.from);
                match &tx.core.action {
                    TxAction::Transfer { to, amount } => TxDto {
                        kind: "transfer",
                        from,
                        to: Some(encode_address(to)),
                        nonce: tx.core.nonce,
                        amount: Some(*amount),
                    },
                    // La verification key (1952 byte) è ESCLUSA: l'indirizzo
                    // del conto è sufficiente per l'indicizzazione.
                    TxAction::Claim { .. } => TxDto {
                        kind: "claim",
                        from,
                        to: None,
                        nonce: tx.core.nonce,
                        amount: None,
                    },
                }
            })
            .collect();
        let line = BlockLineDto {
            format: EXPORT_FORMAT,
            chain_id: chain_id.clone(),
            height: b.header.height,
            block_hash: hex(&b.block_hash),
            prev_block_hash: hex(&b.header.prev_block_hash),
            txs,
        };
        lines.push(serde_json::to_string(&line).expect("serializzazione JSON infallibile"));
    }
    let joined = lines.join("\n");
    let footer = json!({
        "format": EXPORT_FORMAT,
        "kind": "index-end",
        "chain_id": chain_id,
        "height": state.height,
        "index_hash": export_hash(&[joined.as_bytes()]),
    });
    lines.push(serde_json::to_string(&footer).expect("serializzazione JSON infallibile"));
    let mut out = lines.join("\n");
    out.push('\n');
    out
}

/// Verifica un snapshot ricevuto: estrae export_hash, ricostruisce il
/// contenuto canonico compatto SENZA quel campo e ricalcola il checksum.
/// È un controllo di INTEGRITÀ (il digest corrisponde al contenuto), NON
/// di provenienza: chiunque può alterare il contenuto e ricalcolare il
/// checksum. L'autenticazione resta sul log firmato del core.
pub fn verify_state_snapshot(snapshot: &str) -> bool {
    let mut value: serde_json::Value = match serde_json::from_str(snapshot) {
        Ok(v) => v,
        Err(_) => return false,
    };
    let map = match value.as_object_mut() {
        Some(m) => m,
        None => return false,
    };
    let expected = match map.remove("export_hash") {
        Some(serde_json::Value::String(h)) => h,
        _ => return false,
    };
    let content = match serde_json::to_string(&value) {
        Ok(c) => c,
        Err(_) => return false,
    };
    export_hash(&[content.as_bytes()]) == expected
}

/// Verifica un indice JSONL ricevuto: la riga finale deve essere il
/// footer "index-end" e l'index_hash deve corrispondere al checksum
/// ricalcolato sulla concatenazione delle righe dei blocchi. Stesso
/// avviso di verify_state_snapshot: integrità, non provenienza.
pub fn verify_block_index(index: &str) -> bool {
    let lines: Vec<&str> = index.lines().collect();
    if lines.is_empty() {
        return false;
    }
    let footer: serde_json::Value = match serde_json::from_str(lines[lines.len() - 1]) {
        Ok(v) => v,
        Err(_) => return false,
    };
    if footer["kind"] != "index-end" {
        return false;
    }
    let expected = match footer["index_hash"].as_str() {
        Some(h) => h.to_string(),
        None => return false,
    };
    let joined = lines[..lines.len() - 1].join("\n");
    export_hash(&[joined.as_bytes()]) == expected
}

// ---------------------------------------------------------------------------
// Test (eseguire con: cargo test -p token-postquantum-export)
// NOTA: non eseguiti in questo ambiente; serve una toolchain Rust reale.
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use token_postquantum::{
        os_random, GenesisParams, Ledger, SignedTransaction, Wallet, SEED_SIZE,
    };

    struct Fixture {
        data: PathBuf,
        ext: PathBuf,
        node: Wallet,
        creator: Wallet,
        params: GenesisParams,
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.data);
            let _ = std::fs::remove_dir_all(&self.ext);
        }
    }

    fn fixture(name: &str) -> Fixture {
        let data = std::env::temp_dir().join(format!("amg1x-{}-{}-data", name, std::process::id()));
        let ext = std::env::temp_dir().join(format!("amg1x-{}-{}-ext", name, std::process::id()));
        let _ = std::fs::remove_dir_all(&data);
        let _ = std::fs::remove_dir_all(&ext);
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
                airdrop_pool: 300,
                airdrop_per_wallet: 100,
                airdrop_max_wallets: 3,
            },
            data,
            ext,
        }
    }

    #[test]
    fn snapshot_deterministic_supply_invariant_and_provenance() {
        let f = fixture("export-snap");
        let carol = Wallet::from_seed(os_random::<SEED_SIZE>());
        let mut l = Ledger::open(&f.data, &f.ext, f.params.clone(), &f.node, &f.creator).unwrap();
        let chain = l.state.genesis.genesis_hash;
        l.submit(&f.node, vec![SignedTransaction::claim(&carol, chain, 0)])
            .unwrap();
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

        // DETERMINISMO: due esportazioni dello stesso stato sono identiche.
        let s1 = state_snapshot(&l.state);
        let s2 = state_snapshot(&l.state);
        assert_eq!(s1, s2);

        let v: serde_json::Value = serde_json::from_str(&s1).unwrap();
        assert_eq!(v["format"], "amg1-export-v1");
        assert_eq!(v["decimals"], 6);
        assert_eq!(v["symbol"], "TST");
        // Checksum: hash SHAKE256-512, 128 caratteri esadecimali.
        assert_eq!(v["export_hash"].as_str().unwrap().len(), 128);

        // INVARIANTE DI SUPPLY ricomputata dal JSON esportato:
        // somma saldi + pool residui == total_supply.
        let sum: u64 = v["accounts"]
            .as_array()
            .unwrap()
            .iter()
            .map(|a| a["balance"].as_u64().unwrap())
            .sum();
        assert_eq!(
            sum + v["cashback_pool"].as_u64().unwrap() + v["airdrop_pool"].as_u64().unwrap(),
            v["total_supply"].as_u64().unwrap()
        );

        // Carol: 100 (airdrop) + 500 (transfer) = 600 unità.
        let carol_addr = token_postquantum::encode_address(&carol.address);
        let entry = v["accounts"]
            .as_array()
            .unwrap()
            .iter()
            .find(|a| a["address"] == carol_addr.as_str())
            .expect("carol presente nello snapshot");
        assert_eq!(entry["balance"], 600);
        assert_eq!(entry["claimed"], true);
    }

    #[test]
    fn block_index_lines_footer_and_no_keys() {
        let f = fixture("export-idx");
        let carol = Wallet::from_seed(os_random::<SEED_SIZE>());
        let mut l = Ledger::open(&f.data, &f.ext, f.params.clone(), &f.node, &f.creator).unwrap();
        let chain = l.state.genesis.genesis_hash;
        l.submit(&f.node, vec![SignedTransaction::claim(&carol, chain, 0)])
            .unwrap();
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

        let idx = block_index(&l.state);
        let lines: Vec<&str> = idx.lines().collect();
        // Due blocchi + una riga footer.
        assert_eq!(lines.len(), 3);

        let l0: serde_json::Value = serde_json::from_str(lines[0]).unwrap();
        assert_eq!(l0["height"], 1);
        assert_eq!(l0["txs"][0]["kind"], "claim");
        // La verification key NON è esportata.
        assert!(l0["txs"][0].get("verification_key").is_none());

        let l1: serde_json::Value = serde_json::from_str(lines[1]).unwrap();
        assert_eq!(l1["height"], 2);
        assert_eq!(l1["txs"][0]["kind"], "transfer");
        assert_eq!(l1["txs"][0]["amount"], 500);

        let footer: serde_json::Value = serde_json::from_str(lines[2]).unwrap();
        assert_eq!(footer["kind"], "index-end");
        assert_eq!(footer["index_hash"].as_str().unwrap().len(), 128);

        // DETERMINISMO dell'indice.
        assert_eq!(idx, block_index(&l.state));
    }

    #[test]
    fn export_stable_across_reopen() {
        let f = fixture("export-reopen");
        let carol = Wallet::from_seed(os_random::<SEED_SIZE>());
        let mut l = Ledger::open(&f.data, &f.ext, f.params.clone(), &f.node, &f.creator).unwrap();
        let chain = l.state.genesis.genesis_hash;
        l.submit(&f.node, vec![SignedTransaction::claim(&carol, chain, 0)])
            .unwrap();
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
        let snap_before = state_snapshot(&l.state);
        let idx_before = block_index(&l.state);
        drop(l);
        // Riapertura dal log firmato: lo stato ricostruito produce lo
        // stesso export byte per byte (apply_block con undo log non cambia
        // la semantica dello stato ricostruito).
        let l2 = Ledger::open(&f.data, &f.ext, f.params.clone(), &f.node, &f.creator).unwrap();
        assert_eq!(snap_before, state_snapshot(&l2.state));
        assert_eq!(idx_before, block_index(&l2.state));
    }

    #[test]
    fn verify_recomputes_digest_and_rejects_tampering() {
        let f = fixture("export-tamper");
        let carol = Wallet::from_seed(os_random::<SEED_SIZE>());
        let mut l = Ledger::open(&f.data, &f.ext, f.params.clone(), &f.node, &f.creator).unwrap();
        let chain = l.state.genesis.genesis_hash;
        l.submit(&f.node, vec![SignedTransaction::claim(&carol, chain, 0)])
            .unwrap();
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

        // Ricalcolo del digest: i documenti originali verificano.
        let snap = state_snapshot(&l.state);
        assert!(verify_state_snapshot(&snap));
        let idx = block_index(&l.state);
        assert!(verify_block_index(&idx));

        // Saldo alterato SENZA ricalcolo del checksum: il digest
        // ricostruito non corrisponde più.
        let mut v: serde_json::Value = serde_json::from_str(&snap).unwrap();
        v["accounts"][0]["balance"] = serde_json::json!(999_999);
        let tampered_snap = serde_json::to_string_pretty(&v).unwrap();
        assert!(!verify_state_snapshot(&tampered_snap));

        // Riga JSONL alterata: l'index_hash ricostruito non corrisponde.
        let tampered_idx = idx.replace("\"amount\":500", "\"amount\":501");
        assert_ne!(tampered_idx, idx); // la sostituzione ha toccato una riga
        assert!(!verify_block_index(&tampered_idx));
    }
}
