// ============================================================================
// core/src/consts.rs — Costanti crittografiche e limiti (FIPS 204, ML-DSA-65)
// Nessun valore modifica i formati binari: tutti invariati dalla v0.8.
// ============================================================================

// ---------------------------------------------------------------------------
// Costanti crittografiche e limiti (FIPS 204, ML-DSA-65)
// ---------------------------------------------------------------------------
pub(crate) const VK_SIZE: usize = 1952;
pub(crate) const SK_SIZE: usize = 4032;
pub const SIG_SIZE: usize = 3309;
pub const SEED_SIZE: usize = 32;
// Output hash 512 bit: vedi dichiarazione di sicurezza in testa al file.
pub(crate) const HASH_SIZE: usize = 64;

// Domini crittografici a v2: dalla v0.5 hash e address sono a 512 bit; il
// bump del dominio evita OGNI ambiguità con firme/hash della versione a
// 256 bit (stesso messaggio, dominio diverso -> mai verificabile).
pub(crate) const TX_CONTEXT: &[u8] = b"com.amalgam21.tx.v2";
pub(crate) const BLOCK_CONTEXT: &[u8] = b"com.amalgam21.block.v2";
pub(crate) const GENESIS_SIGN_CONTEXT: &[u8] = b"com.amalgam21.genesis.sign.v2";
pub(crate) const ANCHOR_CONTEXT: &[u8] = b"com.amalgam21.anchor.v2";
pub(crate) const ADDR_DOMAIN: &[u8] = b"com.amalgam21.addr.v2";
pub(crate) const GENESIS_DOMAIN: &[u8] = b"com.amalgam21.genesis.v2";
pub(crate) const DERIVE_DOMAIN: &[u8] = b"com.amalgam21.derive.v2";
pub(crate) const ADDR_ENCODING_DOMAIN: &[u8] = b"com.amalgam21.addr.enc.v2";
pub(crate) const FILE_MAGIC: &[u8; 8] = b"AMG2LEDG";
pub(crate) const FILE_VERSION: u32 = 2;
// Checkpoint firmato (v0.13): file NUOVO, nessun formato esistente cambia.
// Versione 2 per coerenza con gli altri formati a firma della catena.
pub(crate) const CKPT_MAGIC: &[u8; 8] = b"AMG2CKPT";
pub(crate) const CKPT_VERSION: u32 = 2;
pub(crate) const CKPT_CONTEXT: &[u8] = b"com.amalgam21.ckpt.v2";
pub(crate) const MAX_CKPT_BYTES: u64 = 1 << 30;
pub(crate) const JOURNAL_MAGIC: &[u8; 8] = b"AMG2JRNL";
pub(crate) const JOURNAL_VERSION: u32 = 2;
pub(crate) const WALLET_MAGIC: &[u8; 8] = b"AMGWALL2";
pub(crate) const WALLET_VERSION: u32 = 2;
pub(crate) const WALLET_KDF_ID: &str = "argon2id";
pub(crate) const WALLET_AEAD_ID: &str = "xchacha20poly1305";

pub(crate) const MAX_WALLET_BYTES: usize = 4096;
pub(crate) const MAX_ANCHOR_BYTES: usize = 4096;
// COMPATIBILITÀ RECORD/BLOCCO: il caso peggiorre è 1024 Claim; ogni Claim
// serializzato = core 2089 B (chain 64 + from 64 + nonce 8 + tag 1 + vk
// 1952) + firma 3313 B (len 4 + 3309) = ~5.4 KiB. Blocco pieno:
// 1024 x 5402 + header + block_hash 64 + firma propositore 3313 ≈ 5.3 MiB.
// Il limite di 8 MiB copre il peggio con margine (con 1 MiB il ledger si
// auto-incompatibilizzava: submit() scriveva record che la rilettura
// rifiutava).
pub(crate) const MAX_RECORD_BYTES: usize = 1 << 23; // 8 MiB
pub(crate) const MAX_TXS_PER_BLOCK: usize = 1024;
pub(crate) const MAX_LOG_BYTES: u64 = 1 << 30;
pub(crate) const MAX_JOURNAL_ENTRIES: usize = 1 << 20;
pub(crate) const MAX_JOURNAL_BYTES: u64 = 1 << 26; // 64 MiB

pub(crate) const MIN_KDF_M_KIB: u32 = 8 * 1024;
// Limiti OPERATIVI al CARICAMENTO: un wallet contraffatto non può imporre
// parametri di KDF atti a negare il servizio. La creazione usa 64 MiB/t=3/p=4.
pub(crate) const MAX_KDF_M_KIB: u32 = 128 * 1024; // 128 MiB
pub(crate) const MAX_KDF_T: u32 = 10;
pub(crate) const MAX_KDF_P: u32 = 8;

/// DECIMALS = 6: 1 token = 1_000_000 unità intere (micro-token). Tutti gli
/// importi (saldi, fee, pool) sono u64 in queste unità: mai virgola mobile.
pub const UNITS_PER_TOKEN: u64 = 1_000_000;

/// Fee fissa della demo: 0.00005 AMG = esattamente 50 unità da 1e-6.
pub const FEE_FIXED_UNITS: u64 = 50;
