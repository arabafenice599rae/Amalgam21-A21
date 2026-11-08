// ============================================================================
// TOKEN DIGITALE PROPRIETARIO POST-QUANTUM — v0.13 (core/src/lib.rs)
// ----------------------------------------------------------------------------
// Cargo.toml (core):
//
//   [package]
//   name = "token-postquantum"
//   version = "0.12.0"
//   edition = "2021"
//
//   [dependencies]
//   sha3 = "0.10"              # RustCrypto SHA-3/SHAKE256 (auditato)
//   libcrux-ml-dsa = "0.0.11"  # ML-DSA-65, FIPS 204, formalmente verificato (Cryspen);
//                              # RUSTSEC-2026-0077 (verifica con norma gamma-1 errata)
//                              # riguarda le versioni <=0.0.7: il pin 0.0.11 è patchato.
//                              # Eseguire `cargo audit` in CI: CE Labs ha avuto
//                              # altre segnalazioni nel 2026.
//   borsh = "1"                # serializzazione canonica deterministica (auditata)
//   bs58 = "0.5"               # base58, ampiamente adottato; nessun audit formale noto
//   rand = "0.10"              # sola entropia OS (TryRngCore)
//   chacha20poly1305 = "0.10"  # AEAD XChaCha20-Poly1305 (RustCrypto, auditato)
//   argon2 = "0.5"             # KDF Argon2id (RustCrypto, PHC winner)
//   zeroize = "1"              # azzeramento sicuro dei segreti in memoria
//   rpassword = "7"            # prompt passphrase senza eco (sostituisce AMG_PASSPHRASE)
//
//   Layout (workspace, dal v0.10):
//     Cargo.toml  = [workspace] resolver = "2", members = ["core", "export"]
//     core/       = questo crate (lib + demo in src/main.rs)
//     export/     = crate token-postquantum-export (snapshot JSON + indice JSONL)
//
// DICHIARAZIONE DI SICUREZZÀ (invariata dalla v0.5):
//   La sicurezza di un hash contro attacchi QUANTISTICI non è (n/2) per ogni
//   proprietà. Con output di n bit:
//     - preimage: Grover dimezza l'esponente -> sicurezza ~2^(n/2);
//     - collision: Brassard-Høyer-Tapp (BHT) porta a ~2^(n/3).
//   Con n=256 bit: ~2^128 preimage ma solo ~2^85 collision (insufficiente per
//   un margine da 128 bit). Per questo gli hash interni (id, catena, anchor)
//   usano SHAKE256 con output a 512 bit: ~2^256 preimage, ~2^170 collision.
//   Le firme restano ML-DSA-65 (NIST livello 3). "Post-quantum" indica primitive
//   senza riduzioni note via Shor/Grover, NON sicurezza assoluta.
//
// CHANGELOG v0.13 (durata, indipendenza, igiene dei segreti — NESSUN formato
// binario esistente cambia; un solo file NUOVO: ledger.ckpt):
//   1. CHECKPOINT FIRMATO: snapshot borsh dello stato contabile (conti,
//      storia dei blocchi, pool) firmato ML-DSA-65 dal nodo su byte
//      canonici con dominio dedicato (com.amalgam21.ckpt.v2). Verifica
//      contro la node_vk del genesis: modello di fiducia identico al
//      record di genesis. Scrittura atomica (tmp + fsync + rename).
//   2. ROTAZIONE DEL LOG: enable_checkpoints(n) attiva il checkpoint +
//      archiviazione del segmento ogni n blocchi (ledger.log.<height>).
//      Ordine crash-safe: checkpoint atomico -> chiusura handle -> rename
//      del segmento -> nuovo log con solo header. Il cap MAX_LOG_BYTES è
//      ora PER SEGMENTO: la storia totale non è più limitata a 1 GiB.
//   3. REPLAY PARZIALE: apertura con segmento ruotato = verifica del
//      segmento (firme di ogni blocco + hash di catena con seme = tip del
//      checkpoint) + replay dei soli blocchi successivi. Cross-check del
//      checkpoint sui segmenti pieni (crash pre-rotazione). Rollback e
//      manomissione rilevati contro journal/anchor in ALTEZZE ASSOLUTE.
//   4. APERTURA STRICT open_independent: rifiuta il montaggio se journal e
//      dati condividono lo stesso filesystem (st_dev): l'indipendenza
//      dichiarata deve essere verificabile, non presunta. open() classico
//      mantiene il comportamento v0.12 (journal su percorso qualunque).
//   5. MLOCK DEI SEGRETI (unix, best-effort): seed e signing key sono
//      spostati su HEAP BOXED (indirizzo stabile agli spostamenti) e le
//      loro pagine sono bloccate in RAM con libc::mlock (standard de
//      facto, rust-lang). Il Drop sblocca PRIMA di azzerare (zeroize
//      esplicito) e deallocare. Errori di lock ignorati di proposito:
//      ambiente senza privilegio resta utilizzabile; l'azzeramento
//      resta la difesa primaria.
//   6. RECOVERY POST-ROTAZIONE: log VUOTO + checkpoint = stato legittimo
//      (prima: "log vuoto + journal non vuoto = incoerente" era l'unico
//      caso). La monotonia journal >= checkpoint è verificata all'apertura.
//
// CHANGELOG v0.12 (performance e igiene, NESSUN formato binario cambia):
//   1. STAGING IN PLACE CON UNDO LOG (modello "conti toccati", alla Solana):
//      validate_and_stage() clonava l'intero LedgerState a ogni blocco —
//      conti E storia completa dei blocchi. Costo O(tutto) per blocco, che
//      degrada in modo lineare con la crescita del ledger (con 200K conti
//      airdrop il solo clone superava 400 MB a blocco). Ora apply_block()
//      muta lo stato in place e tiene uno snapshot SOLO dei conti toccati
//      (derivabile deterministicamente dalla tx: Transfer tocca from/to/
//      sistema; Claim tocca from). Su qualunque errore lo stato è ripristinato
//      byte-identico (undo log in ordine inverso). Semantica all-or-nothing
//      identica; il costo torna O(conti toccati dal blocco).
//   2. INVARIANTE DI SUPPLY INCREMENTALE: accounts_total (u128) è mantenuto
//      per delta a ogni mutazione; il controllo somma saldi + pool ==
//      total_supply è O(1) per blocco invece di O(n conti). La
//      ricomputazione completa resta ad ogni apertura (controllo incrociato
//      incrementale vs riconteggio: incoerenza = TamperDetected). Aritmetica
//      checked_* invariata.
//   3. PRE-VERIFICA FIRME PARALLELA: le firme ML-DSA-65 delle tx di un
//      blocco sono indipendenti dallo stato di mutazione e tra loro: sono
//      verificate in parallelo con std::thread::scope (stabile da 1.63,
//      NESSUNA dipendenza aggiuntiva) prima dell'applicazione sequenziale
//      e deterministica. Conseguenza documentata: per una Transfer da conto
//      INESISTENTE la variante arriva come InvalidSignature (la firma non è
//      verificabile) invece che UnknownAccount; nessun test dipende da
//      UnknownAccount e la semantica di rifiuto è invariata.
//   4. PERMESSI FILE 0o600 (unix): log, anchor, journal e wallet sono creati
//      esplicitamente con mode 0o600 invece di dipendere dall'umask dell'host
//      (su macchina multiutente il default poteva lasciare i segreti leggibili).
//   5. EVIZIONE CONTI NON RECLAMATI A SALDO ZERO: i conti creati da una
//      Transfer verso indirizzo nuovo e mai reclamati (claimed=false,
//      balance=0, nonce=0) erano record morti in mappa per sempre. Sono ora
//      evitti dopo la mutazione che li riporta a zero: ricreabili
//      byte-identico, quindi semantica-preserving. I conti claimed=true NON
//      sono mai evitti (il nonce è storia antifrode). L'undo log ne garantisce
//      il ripristino esatto su rollback.
//   6. ANCHOR: mantenuta la granularità per-blocco. L'amortizzazione (anchor
//      ogni N blocchi) è stata valutata e RIMANDATA: indebolirebbe la finestra
//      di rilevamento del rollback e richiederebbe la rivisitazione dei test
//      journal/rollback. Da rivalutare in un contesto con endpoint esterno.
//   7. CHECKPOINT FIRMATO + ROTAZIONE LOG: RIMANDATI a v0.13. Il design è
//      fissato (snapshot borsh dello stato firmato dal nodo + replay parziale
//      + segmenti di log archiviati) ma non si scrive alla cieca senza
//      compilatore: entrambi toccano il percorso di apertura, che è il punto
//      più sensibile del sistema.
//   8. PASSPHRASE: la demo usa rpassword (prompt senza eco) invece della
//      variabile d'ambiente AMG_PASSPHRASE, leggibile in /proc/<pid>/environ
//      e nei log di crash. Nuova dipendenza del solo crate core.
//
//   9. CORREZIONI DI ALLINEAMENTO applicate alla sincronizzazione del file
//      (il sorgente non era stato compilato; vedi LIMITAZIONI):
//      (a) SYNTAX: WALLET_AEAD_ID presentava un doppio uguale ("= ="):
//          errore di compilazione, corretto.
//      (b) SYNTAX: atomic_write usava OpenOptions::create(&tmp), metodo
//          inesistente: corretto in open(&tmp).
//      (c) SEMANTICA/TEST: la pre-verifica rifiutava con InvalidSignature
//          anche i Transfer da conto ESISTENTE NON reclamato (vk registrata
//          azzerata, firma non verificabile), CONTRASTANDO il test
//          transfer_from_unclaimed_rejected e il passo 4 della demo, che
//          attendono UnclaimedAccount. La pre-verifica ora RINVIA tali tx
//          al controllo sequenziale: l'errore torna ad essere UnclaimedAccount
//          e nessuna spesa non reclamata è possibile (apply_block rifiuta il
//          blocco intero). Per i conti INESISTENTI resta InvalidSignature
//          (punto 3, accettato e documentato).
//   10. CORREZIONE DI SICUREZZA (Claim→Transfer nello stesso blocco): il
//       rinvio del punto 9(c) lasciava un varco: se un Claim nello stesso
//       blocco registrava la vk di un mittente fin lì non reclamato, un
//       Transfer successivo di quel mittente non era verificato da NESSUNA
//       parte (pre-verifica rinviata, applicazione sequenziale senza
//       verifica della firma) e poteva essere accettato con firma
//       contraffatta. Ora apply_block registra l'insieme dei mittenti
//       rinviati e verifica la firma contro la vk appena associata prima
//       di ogni mutazione. Test: forged_transfer_after_claim_same_block_rejected.
//
// CHANGELOG v0.11 (revisione esterna della v0.10, correzioni chirurgiche):
//   1. DEMO: i rami positivi dei controlli negativi terminano con panic!.
//   2. TEST: forged_transfer_signature_rejected nel core.
//   3. EXPORT: hash ridichiarati come CHECKSUM DI INTEGRITÀ non autenticati;
//      canonicalizzazione JSON formalizzata; verify_state_snapshot e
//      verify_block_index pubblici, con test di riapertura e di riga alterata.
// (v0.10, v0.9, v0.8, v0.7, v0.6, v0.5: vedi l'archivio dei changelog —
//  nessun formato binario è mai cambiato dalla v0.8.)
//
// LIMITAZIONI DICHIARATE:
//   - Il codice NON è stato compilato in questo ambiente: serve `cargo check`
//     e `cargo test` su una toolchain reale, poi fuzzing dei parser.
//   - Il journal "esterno" fornisce indipendenza SOLO se risiede su un
//     filesystem/endpoint DIVERSO dai dati (v0.13: open_independent lo
//     impone verificando st_dev; open() classico NON lo impone). Chi
//     controlla l'intero host può sempre riscrivere tutto: l'indipendenza
//     resta una proprietà dell'endpoint di pubblicazione.
//   - Claim e re-claim NON pagano fee: nel modello a propositore unico il
//     costo è zero e non esiste protezione anti-spam; in un modello
//     multipartito sarebbe un vettore di spam da rivalutare.
//   - La copia della signing key imposta PER VALORE dall'API libcrux
//     (MLDSA65SigningKey::new) NON è azzerabile dopo la firma (nessun
//     Drop noto nel crate); i segreti longevi vivono su heap e sono
//     azzerati ESPPLICITAMENTE al rilascio del wallet (Drop). Vedi
//     Wallet::sign.
//   - La facciata ERC-20-like è parità SEMANTICA di lettura, NON
//     compatibilità di protocollo EVM. L'interoperabilità reale richiede un
//     bridge esterno: componente separato, non implementato.
//   - mlock dei segreti (v0.13) è BEST-EFFORT: senza privilegi o con
//     RLIMIT_MEMLOCK basso le pagine NON vengono bloccate e restano
//     eleggibili allo swap; zeroize resta la difesa primaria. Il cap
//     MAX_CKPT_BYTES limita il checkpoint; il cap MAX_LOG_BYTES ora è PER
//     SEGMENTO (la rotazione rimuove il limite alla storia totale).
// ============================================================================
// ---------------------------------------------------------------------------
// STRUTTURA DEL CRATE (modularizzazione v0.13-M1, nessun formato binario
// cambia, API pubblica invariata):
//   consts.rs  = costanti crittografiche e limiti
//   util.rs    = hash SHAKE256, entropia, codifica, tipi base, I/O atomico
//   types.rs   = tipi serializzati (genesis, tx, blocchi, record del log)
//   wallet.rs  = wallet, firme ML-DSA-65, indirizzi, cifratura del wallet
//   anchor.rs  = anchor firmati, journal append-only esterno
//   checkpoint.rs = checkpoint firmato (v0.13): snapshot verificabile
//   error.rs   = errori del ledger
//   state.rs   = stato contabile, undo log, facciata ERC-20-like
//   ledger.rs  = persistenza: log, anchor, journal, apertura e submit
//   tests.rs   = test unitari
// ---------------------------------------------------------------------------

mod anchor;
mod checkpoint;
mod consts;
mod error;
mod ledger;
mod state;
mod types;
mod util;
mod wallet;

#[cfg(test)]
mod tests;

// API pubblica: identica alla v0.12 a singolo file.
pub use anchor::{AnchorFile, AnchorJournal, AnchorPayload};
pub use consts::{FEE_FIXED_UNITS, SEED_SIZE, SIG_SIZE, UNITS_PER_TOKEN};
pub use error::LedgerError;
pub use ledger::Ledger;
pub use state::{Account, LedgerState, ERC20_LIKE_DECIMALS};
pub use types::{
    genesis_identity_hash, Block, BlockHeader, GenesisParams, GenesisRecord, Record,
    SignedTransaction, TxAction, TxCore,
};
pub use util::{fmt_amount, hex, os_random};
pub use wallet::{address_of, decode_address, encode_address, Wallet};

// Riesporti interni (solo i moduli con elementi liberi pub(crate)): i moduli
// vedono gli altri tramite `use crate::*`.
pub(crate) use consts::*;
pub(crate) use util::*;
pub(crate) use wallet::*;
