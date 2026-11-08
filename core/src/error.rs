// ============================================================================
// core/src/error.rs — Errori del ledger.
// ============================================================================

use crate::*;

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
    JournalNotIndependent {
        reason: String,
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
            LedgerError::JournalNotIndependent { reason } => {
                write!(f, "journal non indipendente: {}", reason)
            }
            LedgerError::Io(e) => write!(f, "errore I/O: {}", e),
        }
    }
}
