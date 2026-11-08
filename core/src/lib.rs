// ============================================================================
// TOKEN DIGITALE PROPRIETARIO POST-QUANTUM — v0.12 (core/src/lib.rs)
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
//   - Il journal "esterno" su filesystem locale NON fornisce indipendenza
//     reale: chi controlla il filesystem può riscriverlo. L'indipendenza è
//     una proprietà dell'endpoint, non del codice.
//   - Claim e re-claim NON pagano fee: nel modello a propositore unico il
//     costo è zero e non esiste protezione anti-spam; in un modello
//     multipartito sarebbe un vettore di spam da rivalutare.
//   - La copia della signing key imposta PER VALORE dall'API libcrux
//     (MLDSA65SigningKey::new) NON è azzerabile dopo la firma (nessun
//     Drop noto nel crate); il segreto longevo resta in Zeroizing per
//     l'intera vita del wallet. Vedi Wallet::sign.
//   - La facciata ERC-20-like è parità SEMANTICA di lettura, NON
//     compatibilità di protocollo EVM. L'interoperabilità reale richiede un
//     bridge esterno: componente separato, non implementato.
//   - Checkpoint/rotazione log non implementati (v0.13): il cap di vita
//     resta MAX_LOG_BYTES (1 GiB, ~300K transfer o ~199K claim totali).
//   - mlock/non-swappable della chiave in RAM: non implementato in codice;
//     gestito a livello di deployment (swap cifrato/disattivato, LimitMEMLOCK).
// ============================================================================

use borsh::{BorshDeserialize, BorshSerialize};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use libcrux_ml_dsa::ml_dsa_65;
use rand::{rngs::OsRng, TryRngCore};
use sha3::digest::{ExtendableOutput, Update, XofReader};
use sha3::Shake256;
use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

// ---------------------------------------------------------------------------
// Costanti crittografiche e limiti (FIPS 204, ML-DSA-65)
// ---------------------------------------------------------------------------
const VK_SIZE: usize = 1952;
const SK_SIZE: usize = 4032;
pub const SIG_SIZE: usize = 3309;
pub const SEED_SIZE: usize = 32;
// Output hash 512 bit: vedi dichiarazione di sicurezza in testa al file.
const HASH_SIZE: usize = 64;

// Domini crittografici a v2: dalla v0.5 hash e address sono a 512 bit; il
// bump del dominio evita OGNI ambiguità con firme/hash della versione a
// 256 bit (stesso messaggio, dominio diverso -> mai verificabile).
const TX_CONTEXT: &[u8] = b"com.amalgam21.tx.v2";
const BLOCK_CONTEXT: &[u8] = b"com.amalgam21.block.v2";
const GENESIS_SIGN_CONTEXT: &[u8] = b"com.amalgam21.genesis.sign.v2";
const ANCHOR_CONTEXT: &[u8] = b"com.amalgam21.anchor.v2";
const ADDR_DOMAIN: &[u8] = b"com.amalgam21.addr.v2";
const GENESIS_DOMAIN: &[u8] = b"com.amalgam21.genesis.v2";
const DERIVE_DOMAIN: &[u8] = b"com.amalgam21.derive.v2";
const ADDR_ENCODING_DOMAIN: &[u8] = b"com.amalgam21.addr.enc.v2";
const FILE_MAGIC: &[u8; 8] = b"AMG2LEDG";
const FILE_VERSION: u32 = 2;
const JOURNAL_MAGIC: &[u8; 8] = b"AMG2JRNL";
const JOURNAL_VERSION: u32 = 2;
const WALLET_MAGIC: &[u8; 8] = b"AMGWALL2";
const WALLET_VERSION: u32 = 2;
const WALLET_KDF_ID: &str = "argon2id";
const WALLET_AEAD_ID: &str = "xchacha20poly1305";

const MAX_WALLET_BYTES: usize = 4096;
const MAX_ANCHOR_BYTES: usize = 4096;
// COMPATIBILITÀ RECORD/BLOCCO: il caso peggiorre è 1024 Claim; ogni Claim
// serializzato = core 2089 B (chain 64 + from 64 + nonce 8 + tag 1 + vk
// 1952) + firma 3313 B (len 4 + 3309) = ~5.4 KiB. Blocco pieno:
// 1024 x 5402 + header + block_hash 64 + firma propositore 3313 ≈ 5.3 MiB.
// Il limite di 8 MiB copre il peggio con margine (con 1 MiB il ledger si
// auto-incompatibilizzava: submit() scriveva record che la rilettura
// rifiutava).
const MAX_RECORD_BYTES: usize = 1 << 23; // 8 MiB
const MAX_TXS_PER_BLOCK: usize = 1024;
const MAX_LOG_BYTES: u64 = 1 << 30;
const MAX_JOURNAL_ENTRIES: usize = 1 << 20;
const MAX_JOURNAL_BYTES: u64 = 1 << 26; // 64 MiB

const MIN_KDF_M_KIB: u32 = 8 * 1024;
// Limiti OPERATIVI al CARICAMENTO: un wallet contraffatto non può imporre
// parametri di KDF atti a negare il servizio. La creazione usa 64 MiB/t=3/p=4.
const MAX_KDF_M_KIB: u32 = 128 * 1024; // 128 MiB
const MAX_KDF_T: u32 = 10;
const MAX_KDF_P: u32 = 8;

/// DECIMALS = 6: 1 token = 1_000_000 unità intere (micro-token). Tutti gli
/// importi (saldi, fee, pool) sono u64 in queste unità: mai virgola mobile.
pub const UNITS_PER_TOKEN: u64 = 1_000_000;

/// Fee fissa della demo: 0.00005 AMG = esattamente 50 unità da 1e-6.
pub const FEE_FIXED_UNITS: u64 = 50;

// ---------------------------------------------------------------------------
// Hash post-quantum: SHAKE256, output 512 bit
// ---------------------------------------------------------------------------
fn pq_hash(parts: &[&[u8]]) -> [u8; HASH_SIZE] {
    let mut h = Shake256::default();
    for p in parts {
        h.update(p);
    }
    let mut out = [0u8; HASH_SIZE];
    h.finalize_xof().read(&mut out);
    out
}

pub fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{:02x}", x)).collect()
}

/// Formattazione display di un importo intero in token con 6 decimali.
pub fn fmt_amount(units: u64) -> String {
    format!("{}.{:06}", units / UNITS_PER_TOKEN, units % UNITS_PER_TOKEN)
}

pub fn os_random<const L: usize>() -> [u8; L] {
    let mut buf = [0u8; L];
    OsRng.try_fill_bytes(&mut buf).expect("entropia OS");
    buf
}

/// Deserializzazione borsh STRETTA: rifiuta byte residui.
fn borsh_exact<T: BorshDeserialize>(bytes: &[u8]) -> Result<T, ()> {
    let mut rest = bytes;
    match T::deserialize(&mut rest) {
        Ok(v) if rest.is_empty() => Ok(v),
        _ => Err(()),
    }
}

// ---------------------------------------------------------------------------
// Tipi base
// ---------------------------------------------------------------------------
type Address = [u8; HASH_SIZE];
type Hash = [u8; HASH_SIZE];
type Seed = [u8; SEED_SIZE];

/// Parametri del genesis: TUTTI gli importi sono unità intere (1e-6 token).
/// La politica monetaria è parte del genesis hash: cambiare un parametro
/// produce una catena diversa, irriconciliabile con un ledger esistente.
#[derive(BorshSerialize, BorshDeserialize, Clone, Debug)]
pub struct GenesisParams {
    pub token_name: String,
    pub symbol: String,
    pub total_supply: u64,
    pub domain: String,
    // --- Politica monetaria ---
    /// Allocazione del creatore al genesis.
    pub creator_allocation: u64,
    /// Pool da cui è pagato il cashback delle fee.
    pub fee_pool: u64,
    /// Fee fissa per ogni Transfer, in unità intere.
    pub fee: u64,
    /// Cashback in basis point: 9000 = 90% della fee restituito al mittente.
    pub cashback_bps: u16,
    /// Pool dell'airdrop ai primi wallet.
    pub airdrop_pool: u64,
    /// Airdrop per wallet, concesso alla prima claim del conto.
    pub airdrop_per_wallet: u64,
    /// Numero massimo di wallet beneficiari dell'airdrop.
    pub airdrop_max_wallets: u32,
}

impl GenesisParams {
    /// Coerenza della politica monetaria: rifiuta parametri incoerenti in
    /// modo bloccante, prima di toccare il disco.
    pub fn validate_economics(&self) -> Result<(), LedgerError> {
        let sum = (self.creator_allocation as u128)
            .checked_add(self.fee_pool as u128)
            .and_then(|s| s.checked_add(self.airdrop_pool as u128))
            .ok_or(LedgerError::Overflow)?;
        if sum != self.total_supply as u128 {
            return Err(LedgerError::ConfigMismatch {
                reason: "allocazioni (creatore + fee_pool + airdrop_pool) non sommano alla supply totale".into(),
            });
        }
        if (self.airdrop_per_wallet as u128) * (self.airdrop_max_wallets as u128)
            != self.airdrop_pool as u128
        {
            return Err(LedgerError::ConfigMismatch {
                reason: "airdrop_pool non copre esattamente airdrop_max_wallets beneficiari".into(),
            });
        }
        if self.fee == 0 {
            return Err(LedgerError::ConfigMismatch {
                reason: "fee nulla non ammessa".into(),
            });
        }
        if self.cashback_bps > 10_000 {
            return Err(LedgerError::ConfigMismatch {
                reason: "cashback oltre il 100% della fee".into(),
            });
        }
        Ok(())
    }

    /// Cashback della fee: aritmetica intera esatta sui basis point.
    pub fn cashback_of_fee(&self) -> u64 {
        ((self.fee as u128 * self.cashback_bps as u128) / 10_000) as u64
    }
}

/// Hash di installazione del genesis: VINCOLA i parametri monetari E le
/// identità (chiave del nodo, address e chiave del creatore). È il chain
/// id: due installazioni con le stesse regole ma chiavi diverse producono
/// catene DIVERSE e mutualmente illeggibili.
pub fn genesis_identity_hash(
    params: &GenesisParams,
    node_vk: &[u8; VK_SIZE],
    creator_address: &Address,
    creator_vk: &[u8; VK_SIZE],
) -> Hash {
    #[derive(BorshSerialize)]
    struct GenesisIdentity<'a> {
        params: &'a GenesisParams,
        node_vk: &'a [u8; VK_SIZE],
        creator_address: &'a Address,
        creator_vk: &'a [u8; VK_SIZE],
    }
    let canonical = borsh::to_vec(&GenesisIdentity {
        params,
        node_vk,
        creator_address,
        creator_vk,
    })
    .expect("serializzazione infallibile");
    pq_hash(&[GENESIS_DOMAIN, &canonical])
}

// ---------------------------------------------------------------------------
// Wallet non-custodial a seed indipendente, con segreti zeroizzati
// ---------------------------------------------------------------------------
pub struct Wallet {
    pub seed: Zeroizing<Seed>,
    pub signing_key: Zeroizing<[u8; SK_SIZE]>,
    pub verification_key: [u8; VK_SIZE],
    pub address: Address,
}

impl Wallet {
    pub fn from_seed(seed: Seed) -> Self {
        let kp = ml_dsa_65::generate_key_pair(seed);
        let verification_key = *kp.verification_key.as_ref();
        Wallet {
            seed: Zeroizing::new(seed),
            signing_key: Zeroizing::new(*kp.signing_key.as_ref()),
            address: address_of(&verification_key),
            verification_key,
        }
    }

    /// Utilità OPZIONALE per un singolo utente multi-conto; non è il modello
    /// di sistema: nodo, creator e utenti hanno seed indipendenti.
    pub fn derive_child(master: &Seed, index: u32) -> Wallet {
        let child = pq_hash(&[DERIVE_DOMAIN, master, &index.to_le_bytes()]);
        Wallet::from_seed(child)
    }

    pub fn sign(&self, message: &[u8], context: &[u8]) -> [u8; SIG_SIZE] {
        // IGIENE ZEROIZE (dichiarata): l'API libcrux accetta la chiave per
        // VALORE; la copia dentro MLDSA65SigningKey esce dallo scope alla
        // fine della firma e NON è azzerata (nessun Drop noto nel crate).
        // Con questa API la copia è inevitabile; il segreto longevo resta
        // in Zeroizing per l'intera vita del wallet. Vedi LIMITAZIONI.
        let sk = ml_dsa_65::MLDSA65SigningKey::new(*self.signing_key);
        let sig = ml_dsa_65::sign(&sk, message, context, os_random::<32>())
            .expect("firma ML-DSA-65 con input validi");
        *sig.as_ref()
    }

    pub fn save_encrypted(&self, path: &Path, passphrase: &[u8]) -> std::io::Result<()> {
        #[derive(BorshSerialize)]
        struct WalletFile<'a> {
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
        let salt = os_random::<16>();
        let nonce = os_random::<24>();
        let key = argon2_key(passphrase, &salt, ARGON2_M_KIB, ARGON2_T, ARGON2_P);
        let cipher = XChaCha20Poly1305::new(key.as_ref().into());
        let ct = cipher
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload::from(self.seed.as_ref()),
            )
            .map_err(|_| {
                std::io::Error::new(std::io::ErrorKind::InvalidInput, "cifratura fallita")
            })?;
        let file = WalletFile {
            magic: WALLET_MAGIC,
            version: WALLET_VERSION,
            kdf_id: WALLET_KDF_ID,
            kdf_m_kib: ARGON2_M_KIB,
            kdf_t: ARGON2_T,
            kdf_p: ARGON2_P,
            salt: &salt,
            aead_id: WALLET_AEAD_ID,
            nonce: &nonce,
            ciphertext: &ct,
        };
        let bytes = borsh::to_vec(&file).expect("serializzazione infallibile");
        atomic_write(path, &bytes)
    }

    pub fn load_encrypted(path: &Path, passphrase: &[u8]) -> Result<Self, String> {
        let meta = fs::metadata(path).map_err(|e| e.to_string())?;
        if meta.len() as usize > MAX_WALLET_BYTES {
            return Err("file wallet oltre il limite di dimensione".into());
        }
        let bytes = fs::read(path).map_err(|e| e.to_string())?;
        #[derive(BorshDeserialize)]
        struct WalletFile {
            magic: [u8; 8],
            version: u32,
            kdf_id: String,
            kdf_m_kib: u32,
            kdf_t: u32,
            kdf_p: u32,
            salt: [u8; 16],
            aead_id: String,
            nonce: [u8; 24],
            ciphertext: Vec<u8>,
        }
        let f: WalletFile = borsh_exact(&bytes).map_err(|_| "wallet corrotto".to_string())?;
        if &f.magic != WALLET_MAGIC || f.version != WALLET_VERSION {
            return Err("formato wallet non riconosciuto".into());
        }
        if f.kdf_id != WALLET_KDF_ID || f.aead_id != WALLET_AEAD_ID {
            return Err("algoritmi del wallet non supportati".into());
        }
        if f.kdf_m_kib < MIN_KDF_M_KIB || f.kdf_m_kib > MAX_KDF_M_KIB {
            return Err("parametri Argon2id fuori dai limiti".into());
        }
        if f.kdf_t < 1 || f.kdf_t > MAX_KDF_T || f.kdf_p < 1 || f.kdf_p > MAX_KDF_P {
            return Err("parametri Argon2id fuori dai limiti".into());
        }
        if f.ciphertext.len() != SEED_SIZE + 16 {
            return Err("ciphertext di lunghezza errata".into());
        }
        let key = argon2_key(passphrase, &f.salt, f.kdf_m_kib, f.kdf_t, f.kdf_p);
        let cipher = XChaCha20Poly1305::new(key.as_ref().into());
        let seed = cipher
            .decrypt(
                XNonce::from_slice(&f.nonce),
                Payload::from(f.ciphertext.as_ref()),
            )
            .map_err(|_| "passphrase errata o wallet manomesso".to_string())?;
        if seed.len() != SEED_SIZE {
            return Err("seed di lunghezza errata".into());
        }
        let mut s = [0u8; SEED_SIZE];
        s.copy_from_slice(&seed);
        Ok(Wallet::from_seed(s))
    }
}

const ARGON2_M_KIB: u32 = 65536; // 64 MiB
const ARGON2_T: u32 = 3;
const ARGON2_P: u32 = 4;

fn argon2_key(
    passphrase: &[u8],
    salt: &[u8; 16],
    m_kib: u32,
    t: u32,
    p: u32,
) -> Zeroizing<[u8; 32]> {
    use argon2::{Algorithm, Argon2, Params, Version};
    let params = Params::new(m_kib, t, p, Some(32)).expect("parametri Argon2id validi");
    let mut key = Zeroizing::new([0u8; 32]);
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into(passphrase, salt, key.as_mut())
        .expect("Argon2id con input validi");
    key
}

pub fn address_of(vk: &[u8; VK_SIZE]) -> Address {
    pq_hash(&[ADDR_DOMAIN, vk])
}

/// Codifica PUBBLICA e COMPLETA dell'indirizzo, con checksum:
/// "amg1" + base58(address || checksum). L'address resta internamente
/// [u8; 64]; questa è la forma pubblica di scambio.
pub fn encode_address(addr: &Address) -> String {
    let mut payload = Vec::with_capacity(HASH_SIZE + 4);
    payload.extend_from_slice(addr);
    payload.extend_from_slice(&pq_hash(&[ADDR_ENCODING_DOMAIN, addr])[..4]);
    format!("amg1{}", bs58::encode(&payload).into_string())
}

/// Decodifica e VERIFICA della codifica pubblica: prefisso, alfabeto,
/// lunghezza e checksum. Restituisce l'address binario.
pub fn decode_address(encoded: &str) -> Result<Address, String> {
    let body = encoded
        .strip_prefix("amg1")
        .ok_or("prefisso 'amg1' mancante")?;
    let payload = bs58::decode(body)
        .into_vec()
        .map_err(|_| "base58 non valido")?;
    if payload.len() != HASH_SIZE + 4 {
        return Err("lunghezza del payload errata".into());
    }
    let (addr_bytes, checksum) = payload.split_at(HASH_SIZE);
    if checksum != &pq_hash(&[ADDR_ENCODING_DOMAIN, addr_bytes])[..4] {
        return Err("checksum non valido: indirizzo alterato o trascritto male".into());
    }
    let mut addr = [0u8; HASH_SIZE];
    addr.copy_from_slice(addr_bytes);
    Ok(addr)
}

fn verify_signature(vk: &[u8; VK_SIZE], msg: &[u8], context: &[u8], sig: &[u8]) -> bool {
    if sig.len() != SIG_SIZE {
        return false;
    }
    let mut raw = [0u8; SIG_SIZE];
    raw.copy_from_slice(sig);
    let vk = ml_dsa_65::MLDSA65VerificationKey::new(*vk);
    let signature = ml_dsa_65::MLDSA65Signature::new(raw);
    ml_dsa_65::verify(&vk, msg, context, &signature).is_ok()
}

// ---------------------------------------------------------------------------
// Transazioni: Transfer e Claim, entrambe firmate ML-DSA-65 dal mittente
// ---------------------------------------------------------------------------
#[derive(BorshSerialize, BorshDeserialize, Clone, Debug)]
pub enum TxAction {
    Transfer {
        to: Address,
        amount: u64,
    },
    /// Reclamo del conto: crea il conto se NON esiste (saldo 0, nonce 0);
    /// altrimenti lo vincola alla chiave. In ogni caso prova che il mittente
    /// possiede la chiave privata la cui vk genera esattamente `from`.
    Claim {
        verification_key: [u8; VK_SIZE],
    },
}

#[derive(BorshSerialize, BorshDeserialize, Clone, Debug)]
pub struct TxCore {
    pub chain: Hash,
    pub from: Address,
    pub nonce: u64,
    pub action: TxAction,
}

#[derive(BorshSerialize, BorshDeserialize, Clone, Debug)]
pub struct SignedTransaction {
    pub core: TxCore,
    pub signature: Vec<u8>,
}

impl SignedTransaction {
    fn create(wallet: &Wallet, chain: Hash, nonce: u64, action: TxAction) -> Self {
        let core = TxCore {
            chain,
            from: wallet.address,
            nonce,
            action,
        };
        let canonical = borsh::to_vec(&core).expect("serializzazione infallibile");
        let signature = wallet.sign(&canonical, TX_CONTEXT).to_vec();
        SignedTransaction { core, signature }
    }

    pub fn transfer(wallet: &Wallet, chain: Hash, nonce: u64, to: Address, amount: u64) -> Self {
        Self::create(wallet, chain, nonce, TxAction::Transfer { to, amount })
    }

    pub fn claim(wallet: &Wallet, chain: Hash, nonce: u64) -> Self {
        Self::create(
            wallet,
            chain,
            nonce,
            TxAction::Claim {
                verification_key: wallet.verification_key,
            },
        )
    }

    fn canonical_bytes(&self) -> Vec<u8> {
        borsh::to_vec(&self.core).expect("serializzazione infallibile")
    }
}

// ---------------------------------------------------------------------------
// Blocchi firmati dal nodo propositore
// ---------------------------------------------------------------------------
#[derive(BorshSerialize, BorshDeserialize, Clone, Debug)]
pub struct BlockHeader {
    pub chain: Hash,
    pub height: u64,
    pub prev_block_hash: Hash,
    pub txs: Vec<SignedTransaction>,
}

#[derive(BorshSerialize, BorshDeserialize, Clone, Debug)]
pub struct Block {
    pub header: BlockHeader,
    pub block_hash: Hash,
    pub proposer_signature: Vec<u8>,
}

impl Block {
    fn build(
        chain: Hash,
        height: u64,
        prev_block_hash: Hash,
        txs: Vec<SignedTransaction>,
        node: &Wallet,
    ) -> Self {
        let header = BlockHeader {
            chain,
            height,
            prev_block_hash,
            txs,
        };
        let canonical = borsh::to_vec(&header).expect("serializzazione infallibile");
        let block_hash = pq_hash(&[b"AMG2.BLOCK", &canonical]);
        let proposer_signature = node.sign(&canonical, BLOCK_CONTEXT).to_vec();
        Block {
            header,
            block_hash,
            proposer_signature,
        }
    }

    /// Verifica COMPLETA: hash ricomputato dall'header canonico E firma
    /// ML-DSA-65 del propositore.
    fn verify(&self, node_vk: &[u8; VK_SIZE]) -> bool {
        let canonical = borsh::to_vec(&self.header).expect("serializzazione infallibile");
        if self.block_hash != pq_hash(&[b"AMG2.BLOCK", &canonical]) {
            return false;
        }
        verify_signature(node_vk, &canonical, BLOCK_CONTEXT, &self.proposer_signature)
    }
}

// ---------------------------------------------------------------------------
// Genesis FIRMATO dal nodo
// ---------------------------------------------------------------------------
#[derive(BorshSerialize, BorshDeserialize, Clone, Debug)]
pub struct GenesisRecord {
    pub params: GenesisParams,
    pub genesis_hash: Hash,
    pub node_vk: [u8; VK_SIZE],
    pub creator_address: Address,
    pub creator_vk: [u8; VK_SIZE],
    pub genesis_signature: Vec<u8>,
}

impl GenesisRecord {
    fn canonical_bytes(&self) -> Vec<u8> {
        #[derive(BorshSerialize)]
        struct GenesisCore<'a> {
            params: &'a GenesisParams,
            genesis_hash: &'a Hash,
            node_vk: &'a [u8; VK_SIZE],
            creator_address: &'a Address,
            creator_vk: &'a [u8; VK_SIZE],
        }
        borsh::to_vec(&GenesisCore {
            params: &self.params,
            genesis_hash: &self.genesis_hash,
            node_vk: &self.node_vk,
            creator_address: &self.creator_address,
            creator_vk: &self.creator_vk,
        })
        .expect("serializzazione infallibile")
    }

    fn signed(params: GenesisParams, node: &Wallet, creator: &Wallet) -> Self {
        let genesis_hash = genesis_identity_hash(
            &params,
            &node.verification_key,
            &creator.address,
            &creator.verification_key,
        );
        let mut rec = GenesisRecord {
            genesis_hash,
            params,
            node_vk: node.verification_key,
            creator_address: creator.address,
            creator_vk: creator.verification_key,
            genesis_signature: Vec::new(),
        };
        rec.genesis_signature = node
            .sign(&rec.canonical_bytes(), GENESIS_SIGN_CONTEXT)
            .to_vec();
        rec
    }

    fn verify_signature(&self) -> bool {
        verify_signature(
            &self.node_vk,
            &self.canonical_bytes(),
            GENESIS_SIGN_CONTEXT,
            &self.genesis_signature,
        )
    }

    /// Rifiuta la collisione tra il conto del creatore e il conto di
    /// sistema: quest'ultimo è DERIVATO dalla chiave del nodo; se gli
    /// indirizzi coincidessero, LedgerState::new sovrascriverebbe uno dei
    /// due conti al genesis. Da chiamare SEMPRE prima di costruire lo stato.
    fn check_identity_collision(&self) -> Result<(), LedgerError> {
        if self.creator_address == address_of(&self.node_vk) {
            return Err(LedgerError::ConfigMismatch {
                reason: "l'indirizzo del creatore coincide con il conto di sistema (derivato dalla chiave del nodo)".into(),
            });
        }
        Ok(())
    }
}

#[derive(BorshSerialize, BorshDeserialize, Clone, Debug)]
pub enum Record {
    Genesis(GenesisRecord),
    Block(Block),
}

// ---------------------------------------------------------------------------
// Anchor firmati: file locale + journal append-only esterno
// ---------------------------------------------------------------------------
#[derive(BorshSerialize, BorshDeserialize, Clone, Debug)]
pub struct AnchorPayload {
    pub genesis_hash: Hash,
    pub height: u64,
    pub tip_record_hash: Hash,
}

#[derive(BorshSerialize, BorshDeserialize, Clone, Debug)]
pub struct AnchorFile {
    pub payload: AnchorPayload,
    pub signature: Vec<u8>,
}

impl AnchorFile {
    fn signed(node: &Wallet, payload: AnchorPayload) -> Self {
        let canonical = borsh::to_vec(&payload).expect("serializzazione infallibile");
        let signature = node.sign(&canonical, ANCHOR_CONTEXT).to_vec();
        AnchorFile { payload, signature }
    }

    fn verify(&self, node_vk: &[u8; VK_SIZE]) -> bool {
        let canonical = borsh::to_vec(&self.payload).expect("serializzazione infallibile");
        verify_signature(node_vk, &canonical, ANCHOR_CONTEXT, &self.signature)
    }
}

/// Journal append-only di anchor firmati: l'unico modo "esterno" onesto
/// rappresentabile in un prototipo locale. La semantica è di pubblicazione
/// UNIDIREZIONALE: il ledger APPENDE voci complete e MAI le riscrive;
/// l'unica eccezione è il TRONCAMENTO di una coda incompleta residua di un
/// crash, che non rimuove MAI voci complete.
/// ATTENZIONE (limitazione dichiarata): su filesystem locale chi controlla
/// il filesystem può riscrivere anche il journal. L'indipendenza è una
/// proprietà dell'ENDPOINT (WORM, notarizzazione, timestamping): il percorso
/// qui è un placeholder documentato.
pub struct AnchorJournal {
    path: PathBuf,
}

/// Esito della scansione del journal: ultima voce valida, lunghezza del
/// PREFISSO VALIDO (per troncare una coda incompleta) e numero di voci.
struct JournalScan {
    last: Option<(u64, Hash)>,
    valid_len: usize,
    entries: usize,
}

impl JournalScan {
    const EMPTY: Self = JournalScan {
        last: None,
        valid_len: 0,
        entries: 0,
    };
}

impl AnchorJournal {
    pub fn new(path: PathBuf) -> Self {
        AnchorJournal { path }
    }

    /// Pubblicazione append-only con fsync. Regole:
    ///  - IDEMPOTENTE per (height, tip) già pubblicati;
    ///  - CONTROLLO PREVENTIVO: rifiuta altezze inferiori all'ultima
    ///    pubblicata e tip differenti alla stessa altezza;
    ///  - RIPRISTINO: una eventuale voce finale INCOMPLETA (crash durante
    ///    un append precedente) è TRONCATA prima della nuova voce;
    ///  - LIMITI IN SCRITTURA: dimensione massima e numero di voci sono
    ///    verificati PRIMA di scrivere, non solo in lettura;
    ///  - gli errori di fsync della directory sono PROPAGATI.
    fn publish(&self, node: &Wallet, payload: AnchorPayload) -> Result<bool, std::io::Error> {
        let io_err = |m: &str| std::io::Error::new(std::io::ErrorKind::InvalidData, m);
        let scan = self.scan(&node.verification_key, &payload.genesis_hash)?;
        if let Some((h, tip)) = scan.last {
            if payload.height < h {
                return Err(io_err(
                    "publish rifiutato: altezza inferiore all'ultima pubblicata",
                ));
            }
            if payload.height == h {
                if payload.tip_record_hash != tip {
                    return Err(io_err(
                        "publish rifiutato: tip differente alla stessa altezza",
                    ));
                }
                return Ok(false); // già pubblicato: idempotente
            }
        }
        let file = AnchorFile::signed(node, payload);
        let bytes = borsh::to_vec(&file).expect("serializzazione infallibile");
        // Limiti rispettati ANCHE in scrittura. Il caso di journal da creare
        // CONTA l'header di 12 byte (off-by-12 corretto in v0.8).
        let header_len: u64 = if scan.valid_len == 0 { 12 } else { 0 };
        if (scan.valid_len as u64) + header_len + 4 + (bytes.len() as u64) > MAX_JOURNAL_BYTES {
            return Err(io_err(
                "append rifiutato: journal oltre il limite di dimensione",
            ));
        }
        if scan.entries + 1 > MAX_JOURNAL_ENTRIES {
            return Err(io_err("append rifiutato: journal oltre il limite di voci"));
        }
        let mut f = {
            let mut o = OpenOptions::new();
            o.create(true).append(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                o.mode(0o600);
            }
            o.open(&self.path)?
        };
        let file_len = f.metadata()?.len() as usize;
        if file_len > scan.valid_len {
            // Coda incompleta residua di un crash: il prefisso VALIDO è
            // preservato, la coda è rimossa PRIMA del nuovo append.
            f.set_len(scan.valid_len as u64)?;
            f.sync_all()?;
        }
        if scan.valid_len == 0 {
            f.write_all(JOURNAL_MAGIC)?;
            f.write_all(&JOURNAL_VERSION.to_le_bytes())?;
        }
        f.write_all(&(bytes.len() as u32).to_le_bytes())?;
        f.write_all(&bytes)?;
        f.sync_all()?;
        if let Some(parent) = self.path.parent() {
            File::open(parent)?.sync_all()?;
        }
        Ok(true)
    }

    /// Ultimo anchor pubblicato (vedi scan).
    fn read_last(
        &self,
        node_vk: &[u8; VK_SIZE],
        genesis_hash: &Hash,
    ) -> Result<Option<(u64, Hash)>, std::io::Error> {
        Ok(self.scan(node_vk, genesis_hash)?.last)
    }

    /// Scansione completa del journal. Regole:
    ///  - ogni voce: firma del nodo valida e genesis hash coerente;
    ///  - altezze monotoniche; la voce duplicata (stessa altezza E stesso
    ///    tip) è tollerata SOLO come ultima voce del prefisso valido,
    ///    esattamente come publish() la produce; un duplicato in MEZZO è
    ///    bloccante;
    ///  - una VOCE INCOMPLETA finale è ignorata (crash durante l'append);
    ///    una voce completa ma invalida è errore bloccante.
    fn scan(
        &self,
        node_vk: &[u8; VK_SIZE],
        genesis_hash: &Hash,
    ) -> Result<JournalScan, std::io::Error> {
        let io_err = |m: &str| std::io::Error::new(std::io::ErrorKind::InvalidData, m);
        if !self.path.exists() {
            return Ok(JournalScan::EMPTY);
        }
        let meta = fs::metadata(&self.path)?;
        if meta.len() > MAX_JOURNAL_BYTES {
            return Err(io_err("journal oltre il limite di dimensione"));
        }
        let raw = fs::read(&self.path)?;
        if raw.is_empty() {
            return Ok(JournalScan::EMPTY);
        }
        if raw.len() < 12 || &raw[..8] != JOURNAL_MAGIC {
            return Err(io_err("header journal non valido"));
        }
        let version = u32::from_le_bytes(raw[8..12].try_into().unwrap());
        if version != JOURNAL_VERSION {
            return Err(io_err("versione journal non supportata"));
        }
        let mut scan = JournalScan {
            last: None,
            valid_len: 12,
            entries: 0,
        };
        let mut pos = 12usize;
        let mut pending_duplicate = false;
        while pos < raw.len() {
            if pos + 4 > raw.len() {
                break; // voce finale incompleta (crash): ignorata
            }
            let len = u32::from_le_bytes(raw[pos..pos + 4].try_into().unwrap()) as usize;
            if len == 0 || len > MAX_ANCHOR_BYTES {
                return Err(io_err("dimensione voce journal fuori limiti"));
            }
            if pos + 4 + len > raw.len() {
                break; // voce finale incompleta (crash): ignorata
            }
            let entry = &raw[pos + 4..pos + 4 + len];
            let file: AnchorFile =
                borsh_exact(entry).map_err(|_| io_err("voce journal non deserializzabile"))?;
            if !file.verify(node_vk) {
                return Err(io_err("firma di una voce del journal non valida"));
            }
            if &file.payload.genesis_hash != genesis_hash {
                return Err(io_err("voce del journal di un'altra catena"));
            }
            // Una voce COMPLETA dopo un duplicato: il duplicato non era in
            // coda -> rifiuto.
            if pending_duplicate {
                return Err(io_err("voce duplicata non in coda"));
            }
            let is_duplicate = match scan.last {
                Some((prev_h, prev_tip)) => {
                    if file.payload.height < prev_h {
                        return Err(io_err("altezze non monotoniche nel journal"));
                    }
                    if file.payload.height == prev_h {
                        if file.payload.tip_record_hash != prev_tip {
                            return Err(io_err("voce duplicata con tip differente"));
                        }
                        true
                    } else {
                        false
                    }
                }
                None => false,
            };
            if !is_duplicate {
                scan.last = Some((file.payload.height, file.payload.tip_record_hash));
            }
            pending_duplicate = is_duplicate;
            pos += 4 + len;
            scan.valid_len = pos;
            scan.entries += 1;
            if scan.entries > MAX_JOURNAL_ENTRIES {
                return Err(io_err("journal oltre il limite di voci"));
            }
        }
        Ok(scan)
    }
}

// ---------------------------------------------------------------------------
// Errori
// ---------------------------------------------------------------------------
#[derive(Debug)]
pub enum LedgerError {
    UnknownAccount(Address),
    UnclaimedAccount(Address),
    InsufficientBalance {
        who: Address,
        requested: u64,
        available: u64,
    },
    BadNonce {
        expected: u64,
        got: u64,
    },
    ZeroAmount,
    EmptyBlock,
    Overflow,
    InvalidSignature,
    SupplyInvariantBroken,
    ChainMismatch,
    ConfigMismatch {
        reason: String,
    },
    MissingAnchor {
        source: &'static str,
    },
    NotOperative,
    TamperDetected {
        at_record: u64,
        reason: String,
    },
    RollbackDetected {
        anchor_height: u64,
        log_height: u64,
        source: &'static str,
    },
    Io(std::io::Error),
}

impl From<std::io::Error> for LedgerError {
    fn from(e: std::io::Error) -> Self {
        LedgerError::Io(e)
    }
}

impl std::fmt::Display for LedgerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LedgerError::UnknownAccount(a) => write!(f, "conto sconosciuto {}", encode_address(a)),
            LedgerError::UnclaimedAccount(a) => {
                write!(
                    f,
                    "conto {} non reclamato: serve una transazione Claim firmata",
                    encode_address(a)
                )
            }
            LedgerError::InsufficientBalance {
                who,
                requested,
                available,
            } => {
                write!(
                    f,
                    "saldo insufficiente per {}: richiesto {}, disponibile {}",
                    encode_address(who),
                    requested,
                    available
                )
            }
            LedgerError::BadNonce { expected, got } => {
                write!(
                    f,
                    "nonce non valido: atteso {}, ricevuto {} (replay/doppia spesa)",
                    expected, got
                )
            }
            LedgerError::ZeroAmount => write!(f, "importo nullo o operazione vuota non ammessa"),
            LedgerError::EmptyBlock => write!(f, "nessuna transazione da includere nel blocco"),
            LedgerError::Overflow => write!(f, "overflow aritmetico rilevato"),
            LedgerError::InvalidSignature => write!(f, "firma ML-DSA-65 non valida"),
            LedgerError::SupplyInvariantBroken => write!(f, "invariante di offerta totale violata"),
            LedgerError::ChainMismatch => write!(f, "chain id non corrispondente"),
            LedgerError::ConfigMismatch { reason } => {
                write!(
                    f,
                    "configurazione richiesta non corrisponde al ledger su disco: {}",
                    reason
                )
            }
            LedgerError::MissingAnchor { source } => {
                write!(f, "anchor {} mancante: rifiuto bloccante", source)
            }
            LedgerError::NotOperative => {
                write!(
                    f,
                    "ledger non operativo dopo un errore di persistenza: riaprire il ledger"
                )
            }
            LedgerError::TamperDetected { at_record, reason } => {
                write!(
                    f,
                    "manomissione rilevata (record {}): {}",
                    at_record, reason
                )
            }
            LedgerError::RollbackDetected {
                anchor_height,
                log_height,
                source,
            } => {
                write!(
                    f,
                    "rollback rilevato (anchor {} a quota {} vs log a quota {})",
                    source, anchor_height, log_height
                )
            }
            LedgerError::Io(e) => write!(f, "errore I/O: {}", e),
        }
    }
}

// ---------------------------------------------------------------------------
// Stato: applicazione IN PLACE con undo log (v0.12) e invariante incrementale
// ---------------------------------------------------------------------------
#[derive(Clone, Debug, PartialEq)]
pub struct Account {
    pub balance: u64,
    pub nonce: u64,
    pub verification_key: [u8; VK_SIZE],
    pub claimed: bool,
}

#[derive(Clone)]
pub struct LedgerState {
    pub genesis: GenesisRecord,
    pub accounts: HashMap<Address, Account>,
    /// Somma di TUTTI i saldi contabili, mantenuta INCREMENTALE per delta a
    /// ogni mutazione (v0.12). Invariante per blocco (O(1)):
    ///   accounts_total + cashback_pool + airdrop_pool == total_supply.
    /// Il riconteggio completo avviene una tantum ad ogni apertura: una
    /// incoerenza tra i due è segnalata come manomissione.
    pub accounts_total: u128,
    pub height: u64,
    pub tip_block_hash: Hash,
    pub blocks: Vec<Block>,
    /// Pool monetari residui (unità intere). NON sono conti: sono offerta
    /// non ancora allocata, e rientrano nell'invariante di supply.
    pub cashback_pool: u64,
    pub airdrop_pool: u64,
    /// Contatore dei beneficiari dell'airdrop (primo venito, servito).
    pub airdrop_recipients: u32,
}

/// Registra nello undo log il valore precedente di un conto, se non già
/// registrato in questo blocco. È la base del rollback byte-identico.
fn snapshot_account(
    undo: &mut Vec<(Address, Option<Account>)>,
    accounts: &mut HashMap<Address, Account>,
    addr: &Address,
) {
    if !undo.iter().any(|(a, _)| a == addr) {
        undo.push((*addr, accounts.get(addr).cloned()));
    }
}

/// Evince un conto non reclamato a saldo zero: ricreabile byte-identico
/// (claimed=false, balance=0, nonce=0, vk azzerata), quindi la rimozione è
/// semantica-preserving. I conti claimed=true NON sono mai toccati: il loro
/// nonce è storia antifrode e deve restare registrato.
fn evict_if_unclaimed_zero(accounts: &mut HashMap<Address, Account>, addr: &Address) {
    let dead = matches!(
        accounts.get(addr),
        Some(a) if !a.claimed && a.balance == 0 && a.nonce == 0
    );
    if dead {
        accounts.remove(addr);
    }
}

impl LedgerState {
    fn new(genesis: GenesisRecord) -> Self {
        let genesis_hash = genesis.genesis_hash; // salvato prima del move
        let mut accounts = HashMap::new();
        // Creatore: sola allocazione iniziale, conto reclamato al genesis.
        accounts.insert(
            genesis.creator_address,
            Account {
                balance: genesis.params.creator_allocation,
                nonce: 0,
                verification_key: genesis.creator_vk,
                claimed: true,
            },
        );
        // Conto di SISTEMA (gestore): incassa la quota delle fee. L'address
        // è DERIVATO dalla verification key del nodo, già firmata nel
        // genesis: nessuna chiave aggiuntiva da custodire.
        accounts.insert(
            address_of(&genesis.node_vk),
            Account {
                balance: 0,
                nonce: 0,
                verification_key: genesis.node_vk,
                claimed: true,
            },
        );
        let accounts_total = genesis.params.creator_allocation as u128;
        LedgerState {
            cashback_pool: genesis.params.fee_pool,
            airdrop_pool: genesis.params.airdrop_pool,
            airdrop_recipients: 0,
            genesis,
            accounts,
            accounts_total,
            height: 0,
            tip_block_hash: genesis_hash,
            blocks: Vec::new(),
        }
    }

    pub fn balance(&self, addr: &Address) -> u64 {
        self.accounts.get(addr).map(|a| a.balance).unwrap_or(0)
    }

    pub fn nonce(&self, addr: &Address) -> u64 {
        self.accounts.get(addr).map(|a| a.nonce).unwrap_or(0)
    }

    /// Ripristino byte-identico dello stato dopo un errore di applicazione:
    /// conti nell'ordine inverso dello snapshot, totale contabile ripristinato.
    fn rollback(&mut self, undo: Vec<(Address, Option<Account>)>, old_total: u128) {
        self.accounts_total = old_total;
        for (addr, old) in undo.into_iter().rev() {
            match old {
                Some(acct) => {
                    self.accounts.insert(addr, acct);
                }
                None => {
                    self.accounts.remove(&addr);
                }
            }
        }
    }

    /// Verifica della firma di una tx contro la vk corretta (Transfer: vk
    /// registrata sul conto mittente; Claim: vk allegata). Usata nella fase
    /// di pre-verifica parallela: è puramente READ-ONLY sullo stato.
    fn tx_signature_valid(&self, tx: &SignedTransaction) -> bool {
        let canonical = tx.canonical_bytes();
        match &tx.core.action {
            TxAction::Transfer { .. } => match self.accounts.get(&tx.core.from) {
                // Conto ESISTENTE NON reclamato (correzione v0.12): la vk
                // registrata è AZZERATA, quindi la firma NON è verificabile
                // qui; il rinvio al controllo sequenziale di apply_block
                // restituisce l'errore PRECISO UnclaimedAccount, atteso da
                // transfer_from_unclaimed_rejected e dalla demo. Nessuna
                // spesa non reclamata può passare: apply_block rifiuta il
                // blocco intero (all-or-nothing).
                Some(a) if !a.claimed => true,
                Some(a) => {
                    verify_signature(&a.verification_key, &canonical, TX_CONTEXT, &tx.signature)
                }
                None => false,
            },
            TxAction::Claim { verification_key } => {
                verify_signature(verification_key, &canonical, TX_CONTEXT, &tx.signature)
            }
        }
    }

    /// Pre-verifica parallela di tutte le firme del blocco (v0.12). Le
    /// firme ML-DSA-65 sono indipendenti tra loro e dalle mutazioni di
    /// stato: std::thread::scope (stabile da 1.63, NESSUNA dipendenza
    /// aggiuntiva) la suddivide in chunk sui core disponibili. L'applicazione
    /// resta sequenziale e deterministica: cambia solo la velocità.
    fn preverify_signatures(&self, txs: &[SignedTransaction]) -> bool {
        let n = txs.len();
        let threads = std::thread::available_parallelism()
            .map(|v| v.get())
            .unwrap_or(1)
            .min(n)
            .min(16);
        if threads <= 1 {
            return txs.iter().all(|tx| self.tx_signature_valid(tx));
        }
        let chunk = (n + threads - 1) / threads;
        std::thread::scope(|s| {
            let mut handles = Vec::new();
            for part in txs.chunks(chunk) {
                handles.push(s.spawn(move || part.iter().all(|tx| self.tx_signature_valid(tx))));
            }
            handles.into_iter().all(|h| h.join().unwrap_or(false))
        })
    }

    /// Applicazione IN PLACE di un blocco validato, con undo log (v0.12).
    /// Sostituisce il clone integrale di validate_and_stage(): il costo è
    /// O(conti toccati dal blocco) invece di O(tutto lo stato + la storia).
    /// Semantica all-or-nothing identica: su qualunque errore lo stato è
    /// ripristinato byte-identico. La firma di ogni tx è già stata verificata
    /// da preverify_signatures(); qui restano i controlli dipendenti dallo
    /// stato (esistenza, claimed, nonce, vincolo identità del Claim).
    pub fn apply_block(&mut self, block: &Block) -> Result<(), LedgerError> {
        if !block.verify(&self.genesis.node_vk) {
            return Err(LedgerError::InvalidSignature);
        }
        let h = &block.header;
        if h.txs.is_empty() || h.txs.len() > MAX_TXS_PER_BLOCK {
            return Err(LedgerError::TamperDetected {
                at_record: h.height,
                reason: "numero di transazioni fuori dai limiti".into(),
            });
        }
        if h.chain != self.genesis.genesis_hash {
            return Err(LedgerError::ChainMismatch);
        }
        let next_height = self.height.checked_add(1).ok_or(LedgerError::Overflow)?;
        if h.height != next_height || h.prev_block_hash != self.tip_block_hash {
            return Err(LedgerError::TamperDetected {
                at_record: h.height,
                reason: "catena non continua".into(),
            });
        }
        // Pre-verifica firme: una firma non valida invalida il blocco INTERO,
        // come nella semantica precedente (staging atomico).
        if !self.preverify_signatures(&h.txs) {
            return Err(LedgerError::InvalidSignature);
        }

        // Valori di sola lettura copiati prima della chiusura mutante, così
        // l'applicazione tocca solo accounts/accounts_total/pool.
        let fee = self.genesis.params.fee;
        let cashback_full = self.genesis.params.cashback_of_fee();
        let supply = self.genesis.params.total_supply as u128;
        let system_addr = address_of(&self.genesis.node_vk);
        let airdrop_max = self.genesis.params.airdrop_max_wallets;
        let airdrop_per_wallet = self.genesis.params.airdrop_per_wallet;

        let mut undo: Vec<(Address, Option<Account>)> = Vec::new();
        let old_total = self.accounts_total;

        let mut apply = |state: &mut LedgerState| -> Result<(), LedgerError> {
            for tx in &h.txs {
                if tx.core.chain != state.genesis.genesis_hash {
                    return Err(LedgerError::ChainMismatch);
                }
                match &tx.core.action {
                    TxAction::Transfer { to, amount } => {
                        let sender = state
                            .accounts
                            .get(&tx.core.from)
                            .ok_or(LedgerError::UnknownAccount(tx.core.from))?;
                        if !sender.claimed {
                            return Err(LedgerError::UnclaimedAccount(tx.core.from));
                        }
                        if tx.core.nonce != sender.nonce {
                            return Err(LedgerError::BadNonce {
                                expected: sender.nonce,
                                got: tx.core.nonce,
                            });
                        }
                        if *amount == 0 || tx.core.from == *to {
                            return Err(LedgerError::ZeroAmount);
                        }
                        // FEE FISSA: il mittente paga importo + fee.
                        let debit = (*amount).checked_add(fee).ok_or(LedgerError::Overflow)?;
                        if sender.balance < debit {
                            return Err(LedgerError::InsufficientBalance {
                                who: tx.core.from,
                                requested: debit,
                                available: sender.balance,
                            });
                        }
                        // Cashback: frazione (90%) della fee, limitata al
                        // residuo del pool. Esaurito il pool, cashback 0.
                        let cashback = cashback_full.min(state.cashback_pool);
                        snapshot_account(&mut undo, &mut state.accounts, &tx.core.from);
                        let sender = state.accounts.get_mut(&tx.core.from).expect("presente");
                        sender.balance = sender
                            .balance
                            .checked_sub(debit)
                            .ok_or(LedgerError::Overflow)?;
                        sender.nonce = sender.nonce.checked_add(1).ok_or(LedgerError::Overflow)?;
                        sender.balance = sender
                            .balance
                            .checked_add(cashback)
                            .ok_or(LedgerError::Overflow)?;
                        state.accounts_total = state
                            .accounts_total
                            .checked_sub(debit as u128)
                            .and_then(|t| t.checked_add(cashback as u128))
                            .ok_or(LedgerError::Overflow)?;
                        state.cashback_pool -= cashback;
                        snapshot_account(&mut undo, &mut state.accounts, to);
                        let recipient = state.accounts.entry(*to).or_insert_with(|| Account {
                            balance: 0,
                            nonce: 0,
                            verification_key: [0u8; VK_SIZE],
                            claimed: false,
                        });
                        recipient.balance = recipient
                            .balance
                            .checked_add(*amount)
                            .ok_or(LedgerError::Overflow)?;
                        state.accounts_total = state
                            .accounts_total
                            .checked_add(*amount as u128)
                            .ok_or(LedgerError::Overflow)?;
                        // Fee al sistema: la fee INTERA è accreditata al conto
                        // di sistema; il cashback è pagato dal POOL al
                        // mittente. Conservazione della supply: i saldi
                        // crescono di `cashback` (dal pool) e il pool cala
                        // dello stesso ammontare. Costo netto del mittente:
                        // 10% della fee finché il pool ha fondi, 100% quando
                        // è esaurito.
                        snapshot_account(&mut undo, &mut state.accounts, &system_addr);
                        let system = state
                            .accounts
                            .get_mut(&system_addr)
                            .expect("conto di sistema presente dal genesis");
                        system.balance = system
                            .balance
                            .checked_add(fee)
                            .ok_or(LedgerError::Overflow)?;
                        state.accounts_total = state
                            .accounts_total
                            .checked_add(fee as u128)
                            .ok_or(LedgerError::Overflow)?;
                        // Evizione conto destinatario non reclamato tornato a
                        // saldo zero (record morto ricreabile byte-identico).
                        evict_if_unclaimed_zero(&mut state.accounts, to);
                    }
                    TxAction::Claim { verification_key } => {
                        // Identità vincolata: la vk allegata deve generare
                        // esattamente l'address mittente. (La firma è stata
                        // verificata in pre-verify.)
                        if address_of(verification_key) != tx.core.from {
                            return Err(LedgerError::InvalidSignature);
                        }
                        match state.accounts.get(&tx.core.from) {
                            Some(a) => {
                                // Conto esistente: nonce corrente e nessun
                                // secondo claim con chiave diversa.
                                if tx.core.nonce != a.nonce {
                                    return Err(LedgerError::BadNonce {
                                        expected: a.nonce,
                                        got: tx.core.nonce,
                                    });
                                }
                                if a.claimed && a.verification_key != *verification_key {
                                    return Err(LedgerError::InvalidSignature);
                                }
                            }
                            None => {
                                // Conto INESISTENTE: il Claim lo crea (saldo 0);
                                // il primo nonce di un conto nuovo è 0.
                                if tx.core.nonce != 0 {
                                    return Err(LedgerError::BadNonce {
                                        expected: 0,
                                        got: tx.core.nonce,
                                    });
                                }
                            }
                        }
                        let was_claimed = state
                            .accounts
                            .get(&tx.core.from)
                            .map(|a| a.claimed)
                            .unwrap_or(false);
                        snapshot_account(&mut undo, &mut state.accounts, &tx.core.from);
                        let account =
                            state
                                .accounts
                                .entry(tx.core.from)
                                .or_insert_with(|| Account {
                                    balance: 0,
                                    nonce: 0,
                                    verification_key: [0u8; VK_SIZE],
                                    claimed: false,
                                });
                        account.verification_key = *verification_key;
                        account.claimed = true;
                        account.nonce =
                            account.nonce.checked_add(1).ok_or(LedgerError::Overflow)?;
                        // AIRDROP: concesso una sola volta per conto, alla
                        // prima transizione unclaimed -> claimed, finché il
                        // numero di beneficiari resta sotto il tetto.
                        if !was_claimed && state.airdrop_recipients < airdrop_max {
                            let grant = airdrop_per_wallet.min(state.airdrop_pool);
                            account.balance = account
                                .balance
                                .checked_add(grant)
                                .ok_or(LedgerError::Overflow)?;
                            state.accounts_total = state
                                .accounts_total
                                .checked_add(grant as u128)
                                .ok_or(LedgerError::Overflow)?;
                            state.airdrop_pool -= grant;
                            state.airdrop_recipients += 1;
                        }
                    }
                }
            }
            Ok(())
        };

        if let Err(e) = apply(self) {
            self.rollback(undo, old_total);
            return Err(e);
        }

        // Invariante di supply INCREMENTALE (v0.12): O(1) per blocco.
        let total = self
            .accounts_total
            .checked_add(self.cashback_pool as u128)
            .and_then(|t| t.checked_add(self.airdrop_pool as u128))
            .ok_or(LedgerError::Overflow)?;
        if total != supply {
            self.rollback(undo, old_total);
            return Err(LedgerError::SupplyInvariantBroken);
        }

        self.height = block.header.height;
        self.tip_block_hash = block.block_hash;
        self.blocks.push(block.clone());
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Persistenza: log append-only + anchor locale + journal esterno
// ---------------------------------------------------------------------------
pub struct Ledger {
    pub state: LedgerState,
    log_path: PathBuf,
    anchor_path: PathBuf,
    journal: AnchorJournal,
    tip_record_hash: Hash,
    log: File,
    operational: bool,
}

impl Ledger {
    pub fn open(
        dir: &Path,
        ext_dir: &Path, // PLACEHOLDER: in produzione, endpoint indipendente
        params: GenesisParams,
        node: &Wallet,
        creator: &Wallet,
    ) -> Result<Self, LedgerError> {
        if params.total_supply == 0 {
            return Err(LedgerError::ZeroAmount);
        }
        // La politica monetaria è parte dei parametri: incoerenza bloccante.
        params.validate_economics()?;
        fs::create_dir_all(dir)?;
        fs::create_dir_all(ext_dir)?;
        let log_path = dir.join("ledger.log");
        let anchor_path = dir.join("ledger.anchor");
        let journal = AnchorJournal::new(ext_dir.join("anchor-journal.log"));
        let genesis_hash = genesis_identity_hash(
            &params,
            &node.verification_key,
            &creator.address,
            &creator.verification_key,
        );

        // Un log VUOTO (0 byte: crash tra creazione e prima scrittura) è
        // trattato come assente e reinizializzato; un errore di lettura
        // diverso da NotFound resta BLOCCANTE (mai mascherare un danno).
        let log_has_content = match fs::metadata(&log_path) {
            Ok(m) => m.len() > 0,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => false,
            Err(e) => return Err(e.into()),
        };
        let (genesis_rec, records, loaded_tip) = if log_has_content {
            let (g, r, t) = Self::read_and_verify_log(&log_path, &anchor_path, &journal)?;
            if g.genesis_hash != genesis_hash {
                return Err(LedgerError::ConfigMismatch {
                    reason: "genesis hash differente dai parametri e dalle identità forniti".into(),
                });
            }
            if g.node_vk != node.verification_key {
                return Err(LedgerError::ConfigMismatch {
                    reason: "node verification key differente".into(),
                });
            }
            if g.creator_vk != creator.verification_key {
                return Err(LedgerError::ConfigMismatch {
                    reason: "creator verification key differente".into(),
                });
            }
            if g.creator_address != creator.address {
                return Err(LedgerError::ConfigMismatch {
                    reason: "creator address differente".into(),
                });
            }
            if address_of(&g.creator_vk) != g.creator_address {
                return Err(LedgerError::TamperDetected {
                    at_record: 0,
                    reason: "creator address non deriva dalla creator vk".into(),
                });
            }
            (g, r, t)
        } else {
            // Il log è assente o VUOTO (0 byte: crash prima dell'header).
            // Un crash genuino implica journal VUOTO: le ancore seguono
            // SEMPRE la scrittura del log. Se il journal contiene già voci,
            // lo stato è incoerente (o manipolato): rifiuto bloccante.
            let last = journal
                .read_last(&node.verification_key, &genesis_hash)
                .map_err(|e| LedgerError::TamperDetected {
                    at_record: 0,
                    reason: format!("journal: {}", e),
                })?;
            if last.is_some() {
                return Err(LedgerError::TamperDetected {
                    at_record: 0,
                    reason: "log vuoto ma il journal esterno contiene ancore: stato incoerente"
                        .into(),
                });
            }
            (
                GenesisRecord::signed(params, node, creator),
                Vec::new(),
                genesis_hash,
            )
        };

        // Collisione creatore/conto di sistema rifiutata: senza questo
        // controllo un conto sovrascriverebbe l'altro al genesis.
        genesis_rec.check_identity_collision()?;

        let mut state = LedgerState::new(genesis_rec);
        for (i, rec) in records.iter().enumerate() {
            match rec {
                Record::Block(b) => {
                    state
                        .apply_block(b)
                        .map_err(|e| LedgerError::TamperDetected {
                            at_record: i as u64,
                            reason: format!("blocco non valido: {}", e),
                        })?;
                }
                Record::Genesis(_) => {
                    return Err(LedgerError::TamperDetected {
                        at_record: i as u64,
                        reason: "genesis duplicato".into(),
                    });
                }
            }
        }
        // Controllo incrociato contabile (v0.12): il totale incrementale
        // mantenuto durante il replay deve coincidere con la ricomputazione
        // completa dei saldi. Una incoerenza indica danno o bug contabile:
        // bloccante, mai silenziata.
        let mut full_total: u128 = 0;
        for a in state.accounts.values() {
            full_total = full_total
                .checked_add(a.balance as u128)
                .ok_or(LedgerError::Overflow)?;
        }
        if full_total != state.accounts_total {
            return Err(LedgerError::TamperDetected {
                at_record: 0,
                reason: "invariante contabile incrementale incoerente col riconteggio completo"
                    .into(),
            });
        }

        let mut ledger = Ledger {
            state,
            log_path: log_path.clone(),
            anchor_path,
            journal,
            tip_record_hash: loaded_tip,
            log: {
                let mut o = OpenOptions::new();
                o.create(true).append(true);
                #[cfg(unix)]
                {
                    use std::os::unix::fs::OpenOptionsExt;
                    o.mode(0o600);
                }
                o.open(&log_path)?
            },
            operational: true,
        };
        if fs::metadata(&ledger.log_path)?.len() == 0 {
            let mut head = Vec::new();
            head.extend_from_slice(FILE_MAGIC);
            head.extend_from_slice(&FILE_VERSION.to_le_bytes());
            ledger.log.write_all(&head)?;
            let g = Record::Genesis(ledger.state.genesis.clone());
            ledger.append_record(node, &g, 0)?;
        } else {
            // Recovery: crash tra log e anchor lascia il log avanti; gli
            // anchor sono risincronizzati alla punta del log verificato.
            let height = ledger.state.height;
            let tip = ledger.tip_record_hash;
            ledger.write_anchors(node, height, tip)?;
        }
        Ok(ledger)
    }

    pub fn read_and_verify_log(
        log_path: &Path,
        anchor_path: &Path,
        journal: &AnchorJournal,
    ) -> Result<(GenesisRecord, Vec<Record>, Hash), LedgerError> {
        let meta = fs::metadata(log_path)?;
        if meta.len() > MAX_LOG_BYTES {
            return Err(LedgerError::TamperDetected {
                at_record: 0,
                reason: "log oltre il limite di dimensione".into(),
            });
        }
        let raw = fs::read(log_path)?;
        if raw.len() < 12 || &raw[..8] != FILE_MAGIC {
            return Err(LedgerError::TamperDetected {
                at_record: 0,
                reason: "header file non valido".into(),
            });
        }
        let version = u32::from_le_bytes(raw[8..12].try_into().unwrap());
        if version != FILE_VERSION {
            return Err(LedgerError::TamperDetected {
                at_record: 0,
                reason: "versione file non supportata".into(),
            });
        }
        let mut records: Vec<Record> = Vec::new();
        let mut chain_hashes: Vec<Hash> = Vec::new();
        let mut prev_hash: Option<Hash> = None;
        let mut node_vk: Option<[u8; VK_SIZE]> = None; // dal genesis (record 0)
        let mut pos = 12usize;
        let mut idx = 0u64;
        while pos < raw.len() {
            if pos + 4 > raw.len() {
                return Err(LedgerError::TamperDetected {
                    at_record: idx,
                    reason: "record troncato".into(),
                });
            }
            let len = u32::from_le_bytes(raw[pos..pos + 4].try_into().unwrap()) as usize;
            pos += 4;
            if len == 0 || len > MAX_RECORD_BYTES {
                return Err(LedgerError::TamperDetected {
                    at_record: idx,
                    reason: "dimensione record fuori limiti".into(),
                });
            }
            if pos + len > raw.len() {
                return Err(LedgerError::TamperDetected {
                    at_record: idx,
                    reason: "record troncato".into(),
                });
            }
            let rec_bytes = &raw[pos..pos + len];
            pos += len;
            let rec: Record = borsh_exact(rec_bytes).map_err(|_| LedgerError::TamperDetected {
                at_record: idx,
                reason: "record non deserializzabile o byte residui".into(),
            })?;
            let seed = prev_hash.unwrap_or_else(|| match &rec {
                Record::Genesis(g) => g.genesis_hash,
                Record::Block(_) => [0u8; HASH_SIZE],
            });
            let h = record_chain_hash(&seed, rec_bytes);
            match &rec {
                Record::Genesis(g) => {
                    if idx != 0 {
                        return Err(LedgerError::TamperDetected {
                            at_record: idx,
                            reason: "genesis fuori posizione".into(),
                        });
                    }
                    if g.genesis_hash
                        != genesis_identity_hash(
                            &g.params,
                            &g.node_vk,
                            &g.creator_address,
                            &g.creator_vk,
                        )
                    {
                        return Err(LedgerError::TamperDetected {
                            at_record: idx,
                            reason: "genesis hash non corrisponde a parametri e identità".into(),
                        });
                    }
                    if !g.verify_signature() {
                        return Err(LedgerError::TamperDetected {
                            at_record: idx,
                            reason: "firma del genesis non valida".into(),
                        });
                    }
                    node_vk = Some(g.node_vk);
                }
                Record::Block(b) => {
                    // VERIFICA COMPLETA DI OGNI BLOCCO: firma del propositore
                    // oltre all'hash dell'header.
                    let vk = node_vk.ok_or_else(|| LedgerError::TamperDetected {
                        at_record: idx,
                        reason: "blocco prima del genesis".into(),
                    })?;
                    if !b.verify(&vk) {
                        return Err(LedgerError::TamperDetected {
                            at_record: idx,
                            reason: "firma del propositore non valida".into(),
                        });
                    }
                }
            }
            prev_hash = Some(h);
            chain_hashes.push(h);
            records.push(rec);
            idx += 1;
        }
        if records.is_empty() || !matches!(records[0], Record::Genesis(_)) {
            return Err(LedgerError::TamperDetected {
                at_record: 0,
                reason: "genesis mancante".into(),
            });
        }
        let genesis = match records.remove(0) {
            Record::Genesis(g) => g,
            _ => unreachable!(),
        };
        let log_height = records.len() as u64;
        let tip_record_hash = chain_hashes.last().copied().unwrap_or(genesis.genesis_hash);

        // ANCHOR LOCALE (file firmato, riscrivibile): controllo rapido.
        if !anchor_path.exists() {
            return Err(LedgerError::MissingAnchor { source: "locale" });
        }
        let bytes = fs::read(anchor_path)?;
        if bytes.len() > MAX_ANCHOR_BYTES {
            return Err(LedgerError::TamperDetected {
                at_record: 0,
                reason: "anchor oltre il limite di dimensione".into(),
            });
        }
        let file: AnchorFile = borsh_exact(&bytes).map_err(|_| LedgerError::TamperDetected {
            at_record: 0,
            reason: "anchor corrotto o con byte residui".into(),
        })?;
        if !file.verify(&genesis.node_vk) {
            return Err(LedgerError::TamperDetected {
                at_record: 0,
                reason: "firma dell'anchor non valida".into(),
            });
        }
        if file.payload.genesis_hash != genesis.genesis_hash {
            return Err(LedgerError::TamperDetected {
                at_record: 0,
                reason: "anchor di un'altra catena".into(),
            });
        }
        if file.payload.height > log_height {
            return Err(LedgerError::RollbackDetected {
                anchor_height: file.payload.height,
                log_height,
                source: "locale",
            });
        }
        let idx_local = file.payload.height as usize;
        if idx_local >= chain_hashes.len()
            || file.payload.tip_record_hash != chain_hashes[idx_local]
        {
            return Err(LedgerError::TamperDetected {
                at_record: file.payload.height,
                reason: "catena dei record non corrisponde all'anchor locale".into(),
            });
        }

        // JOURNAL ESTERNO (append-only, firmato, monotono): la traccia che
        // sopravvive al ripristino simultaneo di log e anchor locali.
        let last = journal
            .read_last(&genesis.node_vk, &genesis.genesis_hash)
            .map_err(|e| LedgerError::TamperDetected {
                at_record: 0,
                reason: format!("journal: {}", e),
            })?;
        let (j_height, j_tip) = match last {
            Some(x) => x,
            None => {
                return Err(LedgerError::MissingAnchor {
                    source: "esterno (journal)",
                })
            }
        };
        if j_height > log_height {
            return Err(LedgerError::RollbackDetected {
                anchor_height: j_height,
                log_height,
                source: "esterno (journal)",
            });
        }
        let idx_journal = j_height as usize;
        if idx_journal >= chain_hashes.len() || j_tip != chain_hashes[idx_journal] {
            return Err(LedgerError::TamperDetected {
                at_record: j_height,
                reason: "catena dei record non corrisponde al journal esterno".into(),
            });
        }
        Ok((genesis, records, tip_record_hash))
    }

    fn append_record(
        &mut self,
        node: &Wallet,
        rec: &Record,
        new_height: u64,
    ) -> Result<(), LedgerError> {
        let old_tip = self.tip_record_hash;
        let bytes = borsh::to_vec(rec).map_err(|_| LedgerError::Overflow)?;
        let new_tip = record_chain_hash(&old_tip, &bytes);
        let len_bytes = (bytes.len() as u32).to_le_bytes();
        let result: Result<(), LedgerError> = (|| {
            self.log.write_all(&len_bytes)?;
            self.log.write_all(&bytes)?;
            self.log.sync_all()?;
            self.write_anchors(node, new_height, new_tip)?;
            Ok(())
        })();
        match result {
            Ok(()) => {
                self.tip_record_hash = new_tip;
                Ok(())
            }
            Err(e) => {
                self.operational = false;
                Err(e)
            }
        }
    }

    fn write_anchors(&self, node: &Wallet, height: u64, tip: Hash) -> Result<(), LedgerError> {
        let payload = AnchorPayload {
            genesis_hash: self.state.genesis.genesis_hash,
            height,
            tip_record_hash: tip,
        };
        let file = AnchorFile::signed(node, payload.clone());
        let bytes = borsh::to_vec(&file).map_err(|_| LedgerError::Overflow)?;
        atomic_write(&self.anchor_path, &bytes)?;
        // Pubblicazione append-only (idempotente) verso il journal esterno.
        self.journal.publish(node, payload)?;
        Ok(())
    }

    pub fn submit(
        &mut self,
        node: &Wallet,
        txs: Vec<SignedTransaction>,
    ) -> Result<(), LedgerError> {
        if !self.operational {
            return Err(LedgerError::NotOperative);
        }
        if txs.is_empty() {
            return Err(LedgerError::EmptyBlock);
        }
        let next_height = self
            .state
            .height
            .checked_add(1)
            .ok_or(LedgerError::Overflow)?;
        let block = Block::build(
            self.state.genesis.genesis_hash,
            next_height,
            self.state.tip_block_hash,
            txs,
            node,
        );
        // Applicazione IN PLACE con undo log: se fallisce, lo stato è
        // byte-identico e il blocco non viene scritto.
        self.state.apply_block(&block)?;
        self.append_record(node, &Record::Block(block), self.state.height)?;
        Ok(())
    }
}

fn record_chain_hash(prev: &Hash, rec_bytes: &[u8]) -> Hash {
    pq_hash(&[b"AMG2.REC", prev, rec_bytes])
}

/// Scrittura atomica: temporaneo + fsync file + rename + fsync directory.
/// Gli errori di fsync della DIRECTORY sono PROPAGATI. I file sono creati
/// con permessi 0o600 (unix): log, anchor, journal e wallet non dipendono
/// dall'umask dell'host.
fn atomic_write(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let tmp = path.with_extension("tmp");
    {
        let mut f = {
            let mut o = OpenOptions::new();
            o.write(true).create(true).truncate(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                o.mode(0o600);
            }
            o.open(&tmp)?
        };
        f.write_all(bytes)?;
        f.sync_all()?;
    }
    fs::rename(&tmp, path)?;
    if let Some(parent) = path.parent() {
        File::open(parent)?.sync_all()?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Facciata ERC-20-like (v0.9): parità SEMANTICA di lettura
// ---------------------------------------------------------------------------
// Rende il ledger interrogabile con la stessa semantica di un token ERC-20
// (name, symbol, decimals, totalSupply, balanceOf). NON è compatibilità di
// protocollo: ERC-20 risiede su chain EVM con firme secp256k1 e indirizzi a
// 20 byte; qui le firme sono ML-DSA-65 e gli indirizzi (64 byte, "amg1" +
// base58 con checksum) derivano dalla chiave post-quantum.

/// Decimali secondo la convenzione dei token tradizionali: 6 (USDC/USDT).
pub const ERC20_LIKE_DECIMALS: u8 = 6;

impl LedgerState {
    /// name() secondo la semantica ERC-20.
    pub fn erc20_name(&self) -> &str {
        &self.genesis.params.token_name
    }

    /// symbol() secondo la semantica ERC-20.
    pub fn erc20_symbol(&self) -> &str {
        &self.genesis.params.symbol
    }

    /// decimals() secondo la semantica ERC-20 (6, come USDC/USDT).
    pub fn erc20_decimals(&self) -> u8 {
        ERC20_LIKE_DECIMALS
    }

    /// totalSupply() secondo la semantica ERC-20, in unità intere da 1e-6.
    pub fn erc20_total_supply(&self) -> u64 {
        self.genesis.params.total_supply
    }

    /// balanceOf(addr) secondo la semantica ERC-20, in unità intere:
    /// 0 per indirizzi mai visti, come in ERC-20.
    pub fn erc20_balance_of(&self, addr: &Address) -> u64 {
        self.balance(addr)
    }
}

// ---------------------------------------------------------------------------
// Test (eseguire con: cargo test)
// NOTA: non eseguiti in questo ambiente; servono una toolchain Rust reale.
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;

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
            let mut l =
                Ledger::open(&f.data, &f.ext, f.params.clone(), &f.node, &f.creator).unwrap();
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
                .open(&f.ext.join("anchor-journal.log"))
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
        fs::write(&path, &borsh::to_vec(&file).unwrap()).unwrap();
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
            let mut l =
                Ledger::open(&f.data, &f.ext, f.params.clone(), &f.node, &f.creator).unwrap();
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
            let mut l =
                Ledger::open(&f.data, &f.ext, f.params.clone(), &f.node, &f.creator).unwrap();
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
}
