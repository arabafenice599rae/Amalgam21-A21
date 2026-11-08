// ============================================================================
// core/src/checkpoint.rs — Checkpoint firmato (v0.13): snapshot borsh dello
// stato contabile firmato dal nodo. È la base del replay parziale del log e
// della rotazione dei segmenti: il file ledger.ckpt è NUOVO, nessun formato
// binario esistente cambia.
// ============================================================================

use crate::*;

use borsh::{BorshDeserialize, BorshSerialize};
use std::fs;
use std::path::Path;

/// Corpo del checkpoint: stato completo, altezza raggiunta e hash di catena
/// dell'ultimo record applicato. tip_record_hash è il seme di continuità per
/// il segmento di log scritto dopo la rotazione.
#[derive(BorshSerialize, BorshDeserialize)]
pub(crate) struct CheckpointBody {
    pub genesis_hash: Hash,
    pub height: u64,
    pub tip_record_hash: Hash,
    pub state: LedgerState,
}

/// Checkpoint verificato, pronto per il replay parziale.
pub(crate) struct Checkpoint {
    pub genesis_hash: Hash,
    pub height: u64,
    pub tip_record_hash: Hash,
    pub state: LedgerState,
}

/// Scrive il checkpoint in modo atomico e sincronizzato. Il file contiene
/// magic + versione + corpo borsh + firma ML-DSA-65 del nodo su TUTTI i byte
/// canonici che precedono la firma. La scrittura PRECEDE sempre l'archiviazione
/// del segmento di log: un crash intermedio lascia uno stato riapribile.
pub(crate) fn write(
    path: &Path,
    node: &Wallet,
    state: &LedgerState,
    height: u64,
    tip_record_hash: Hash,
) -> Result<(), LedgerError> {
    let body = CheckpointBody {
        genesis_hash: state.genesis.genesis_hash,
        height,
        tip_record_hash,
        state: state.clone(),
    };
    let mut canonical = Vec::with_capacity(8192);
    canonical.extend_from_slice(CKPT_MAGIC);
    canonical.extend_from_slice(&CKPT_VERSION.to_le_bytes());
    canonical.extend_from_slice(&borsh::to_vec(&body).map_err(|_| LedgerError::Overflow)?);
    let sig = node.sign(&canonical, CKPT_CONTEXT);
    canonical.extend_from_slice(&sig);
    atomic_write(path, &canonical)
}

/// Legge e verifica il checkpoint: la firma ML-DSA-65 del nodo è verificata
/// contro la node_vk del genesis contenuta nello stato. Il modello di
/// fiducia è identale a quello del record di genesis: firmare richiede la
/// chiave di firma del nodo, non replicabile da chi accede al filesystem.
pub(crate) fn read(path: &Path) -> Result<Checkpoint, LedgerError> {
    let meta = fs::metadata(path)?;
    if meta.len() > MAX_CKPT_BYTES {
        return Err(LedgerError::TamperDetected {
            at_record: 0,
            reason: "checkpoint oltre il limite di dimensione".into(),
        });
    }
    let raw = fs::read(path)?;
    if raw.len() < 12 + SIG_SIZE || &raw[..8] != CKPT_MAGIC {
        return Err(LedgerError::TamperDetected {
            at_record: 0,
            reason: "header checkpoint non valido".into(),
        });
    }
    let version = u32::from_le_bytes(raw[8..12].try_into().expect("slice di 4 byte"));
    if version != CKPT_VERSION {
        return Err(LedgerError::TamperDetected {
            at_record: 0,
            reason: "versione checkpoint non supportata".into(),
        });
    }
    let split = raw.len() - SIG_SIZE;
    let body: CheckpointBody =
        borsh_exact(&raw[12..split]).map_err(|_| LedgerError::TamperDetected {
            at_record: 0,
            reason: "checkpoint non deserializzabile o con byte residui".into(),
        })?;
    if !verify_signature(
        &body.state.genesis.node_vk,
        &raw[..split],
        CKPT_CONTEXT,
        &raw[split..],
    ) {
        return Err(LedgerError::InvalidSignature);
    }
    if body.genesis_hash != body.state.genesis.genesis_hash {
        return Err(LedgerError::TamperDetected {
            at_record: 0,
            reason: "genesis del checkpoint incoerente con lo stato".into(),
        });
    }
    Ok(Checkpoint {
        genesis_hash: body.genesis_hash,
        height: body.height,
        tip_record_hash: body.tip_record_hash,
        state: body.state,
    })
}
