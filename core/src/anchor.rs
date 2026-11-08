// ============================================================================
// core/src/anchor.rs — Anchor firmati: file locale + journal append-only esterno.
// ============================================================================

use crate::*;

use borsh::{BorshDeserialize, BorshSerialize};
use std::fs::OpenOptions;
use std::fs::{self, File};
use std::io::Write;
use std::path::PathBuf;

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
    pub(crate) fn signed(node: &Wallet, payload: AnchorPayload) -> Self {
        let canonical = borsh::to_vec(&payload).expect("serializzazione infallibile");
        let signature = node.sign(&canonical, ANCHOR_CONTEXT).to_vec();
        AnchorFile { payload, signature }
    }

    pub(crate) fn verify(&self, node_vk: &[u8; VK_SIZE]) -> bool {
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
    pub(crate) fn publish(
        &self,
        node: &Wallet,
        payload: AnchorPayload,
    ) -> Result<bool, std::io::Error> {
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
    pub(crate) fn read_last(
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
