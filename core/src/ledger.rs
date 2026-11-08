// ============================================================================
// core/src/ledger.rs — Persistenza: log append-only + anchor locale + journal.
// ============================================================================

use crate::*;

use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

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
            let seed = prev_hash.unwrap_or(match &rec {
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
