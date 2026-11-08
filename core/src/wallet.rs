// ============================================================================
// core/src/wallet.rs — Wallet non-custodial a seed indipendente, firme ML-DSA-65,
// indirizzi, cifratura del wallet (Argon2id + XChaCha20-Poly1305).
// ============================================================================

use crate::*;

use borsh::{BorshDeserialize, BorshSerialize};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use libcrux_ml_dsa::ml_dsa_65;
use std::fs;
use std::path::Path;
use zeroize::Zeroizing;

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
        // Truncamento deliberato a 32 byte (prima metà del digest Shake256-512):
        // il seed ML-DSA-65 è 32 byte e la derivazione non deve ampliare
        // l'entropia del master.
        let mut seed = Seed::default();
        seed.copy_from_slice(&child[..SEED_SIZE]);
        Wallet::from_seed(seed)
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

pub(crate) fn verify_signature(vk: &[u8; VK_SIZE], msg: &[u8], context: &[u8], sig: &[u8]) -> bool {
    if sig.len() != SIG_SIZE {
        return false;
    }
    let mut raw = [0u8; SIG_SIZE];
    raw.copy_from_slice(sig);
    let vk = ml_dsa_65::MLDSA65VerificationKey::new(*vk);
    let signature = ml_dsa_65::MLDSA65Signature::new(raw);
    ml_dsa_65::verify(&vk, msg, context, &signature).is_ok()
}
