// ============================================================================
// core/src/util.rs — Primitive condivise: hash SHAKE256, entropia, codifica,
// tipi base, hash di catena dei record, scrittura atomica dei file.
// ============================================================================

use crate::*;

use borsh::BorshDeserialize;
use rand::{rngs::SysRng, TryRng};
use sha3::digest::{ExtendableOutput, Update, XofReader};
use sha3::Shake256;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::Path;

// ---------------------------------------------------------------------------
// Hash post-quantum: SHAKE256, output 512 bit
// ---------------------------------------------------------------------------
pub(crate) fn pq_hash(parts: &[&[u8]]) -> [u8; HASH_SIZE] {
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
    SysRng.try_fill_bytes(&mut buf).expect("entropia OS");
    buf
}

/// Deserializzazione borsh STRETTA: rifiuta byte residui.
pub(crate) fn borsh_exact<T: BorshDeserialize>(bytes: &[u8]) -> Result<T, ()> {
    let mut rest = bytes;
    match T::deserialize(&mut rest) {
        Ok(v) if rest.is_empty() => Ok(v),
        _ => Err(()),
    }
}

// ---------------------------------------------------------------------------
// Tipi base
// ---------------------------------------------------------------------------
pub(crate) type Address = [u8; HASH_SIZE];
pub(crate) type Hash = [u8; HASH_SIZE];
pub(crate) type Seed = [u8; SEED_SIZE];

pub(crate) fn record_chain_hash(prev: &Hash, rec_bytes: &[u8]) -> Hash {
    pq_hash(&[b"AMG2.REC", prev, rec_bytes])
}

/// Scrittura atomica: temporaneo + fsync file + rename + fsync directory.
/// Gli errori di fsync della DIRECTORY sono PROPAGATI. I file sono creati
/// con permessi 0o600 (unix): log, anchor, journal e wallet non dipendono
/// dall'umask dell'host.
pub(crate) fn atomic_write(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
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
