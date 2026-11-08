// ============================================================================
// core/src/ledger.rs — Persistenza: log append-only + anchor locale + journal
// esterno. v0.13: checkpoint firmato con rotazione dei segmenti di log e
// apertura STRICT che rifiuta journal sullo stesso device dei dati.
// ============================================================================

use crate::*;

use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

/// Vista del checkpoint usata dalla verifica del log segmentato.
pub(crate) struct CheckpointView<'a> {
    pub genesis: &'a GenesisRecord,
    pub height: u64,
    pub tip_record_hash: Hash,
}

pub struct Ledger {
    pub state: LedgerState,
    log_dir: PathBuf,
    log_path: PathBuf,
    anchor_path: PathBuf,
    ckpt_path: PathBuf,
    journal: AnchorJournal,
    tip_record_hash: Hash,
    log: Option<File>,
    /// Politica di rotazione (v0.13): Some(n) = checkpoint + archiviazione
    /// del segmento ogni n blocchi; None = comportamento v0.12 (segmento
    /// unico, cap MAX_LOG_BYTES).
    ckpt_every: Option<u64>,
    last_ckpt_height: u64,
    operational: bool,
}

fn open_append(path: &Path) -> Result<File, LedgerError> {
    let mut o = OpenOptions::new();
    o.create(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.mode(0o600);
    }
    Ok(o.open(path)?)
}

/// Creazione/azzeramento del log: header-only (0 o 12 byte residui di un
/// crash durante l'apertura) e nessun checkpoint => il log è NUOVO, va
/// riscritto da zero con truncate per non accumulare header doppi.
fn open_fresh(path: &Path) -> Result<File, LedgerError> {
    // write+create+truncate: combinazione canonica (append+truncate è
    // rifiutata dalla std). Le scritture successive avvengono in sequenza
    // sullo STESSO handle, quindi O_APPEND non è necessario.
    let mut o = OpenOptions::new();
    o.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.mode(0o600);
    }
    Ok(o.open(path)?)
}

impl Ledger {
    pub fn open(
        dir: &Path,
        ext_dir: &Path,
        params: GenesisParams,
        node: &Wallet,
        creator: &Wallet,
    ) -> Result<Self, LedgerError> {
        Self::open_inner(dir, ext_dir, params, node, creator, false)
    }

    /// Apertura STRICT (v0.13): rifiuta l'apertura se il journal risiede sul
    /// STESSO filesystem dei dati. In quel caso non esiste indipendenza
    /// reale: chi controlla il filesystem può riscrivere anche il journal.
    /// L'indipendenza è una proprietà dell'endpoint: questa verifica la
    /// impone a monte (st_dev differente) invece di dichiararla altrove.
    pub fn open_independent(
        dir: &Path,
        ext_dir: &Path,
        params: GenesisParams,
        node: &Wallet,
        creator: &Wallet,
    ) -> Result<Self, LedgerError> {
        Self::open_inner(dir, ext_dir, params, node, creator, true)
    }

    fn open_inner(
        dir: &Path,
        ext_dir: &Path,
        params: GenesisParams,
        node: &Wallet,
        creator: &Wallet,
        strict_ext: bool,
    ) -> Result<Self, LedgerError> {
        if params.total_supply == 0 {
            return Err(LedgerError::ZeroAmount);
        }
        // La politica monetaria è parte dei parametri: incoerenza bloccante.
        params.validate_economics()?;
        fs::create_dir_all(dir)?;
        fs::create_dir_all(ext_dir)?;
        #[cfg(unix)]
        if strict_ext {
            use std::os::unix::fs::MetadataExt;
            let dev_data = fs::metadata(dir)?.dev();
            let dev_ext = fs::metadata(ext_dir)?.dev();
            if dev_data == dev_ext {
                return Err(LedgerError::JournalNotIndependent {
                    reason: "journal e dati sullo stesso device (st_dev identico)".into(),
                });
            }
        }
        let log_path = dir.join("ledger.log");
        let anchor_path = dir.join("ledger.anchor");
        let ckpt_path = dir.join("ledger.ckpt");
        let journal = AnchorJournal::new(ext_dir.join("anchor-journal.log"));
        let genesis_hash = genesis_identity_hash(
            &params,
            &node.verification_key,
            &creator.address,
            &creator.verification_key,
        );

        // Checkpoint firmato (v0.13), se presente.
        let ck = if ckpt_path.exists() {
            let c = checkpoint::read(&ckpt_path)?;
            if c.genesis_hash != genesis_hash {
                return Err(LedgerError::ConfigMismatch {
                    reason: "checkpoint di un'altra catena (genesis hash diverso)".into(),
                });
            }
            Some(c)
        } else {
            None
        };

        // Un log VUOTO (0 byte: crash tra creazione e prima scrittura) è
        // trattato come assente; un log HEADER-ONLY (esattamente 12 byte:
        // stato legittimo IMMEDIATAMENTE DOPO una rotazione, o crash tra
        // header e genesis in apertura fresh) segue lo stesso percorso di
        // recovery: contiene ZERO record. Un log di 1-11 byte NON è vuoto
        // né valido: finisce nella verifica e viene rifiutato come header
        // corrotto (danno, non crash). Un errore di lettura diverso da
        // NotFound resta BLOCCANTE (mai mascherare un danno).
        let log_has_records = match fs::metadata(&log_path) {
            Ok(m) => !(m.len() == 0 || m.len() == 12),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => false,
            Err(e) => return Err(e.into()),
        };
        let (full_mode, genesis_rec, records, loaded_tip) = if log_has_records {
            let base = ck.as_ref().map(|c| CheckpointView {
                genesis: &c.state.genesis,
                height: c.height,
                tip_record_hash: c.tip_record_hash,
            });
            let (g, recs, tip) =
                Self::read_and_verify_log_base(&log_path, &anchor_path, &journal, base.as_ref())?;
            let rotated = g.is_none();
            let genesis_rec = match g {
                Some(g0) => g0,
                None => ck
                    .as_ref()
                    .expect("segmento ruotato implica checkpoint")
                    .state
                    .genesis
                    .clone(),
            };
            (!rotated, genesis_rec, recs, tip)
        } else {
            // Log assente o VUOTO (0 byte).
            match &ck {
                Some(c) => {
                    // Recovery post-rotazione: il log NUOVO parte vuoto,
                    // SENZA genesis: la catena dei record continua dal
                    // checkpoint. La punta deve essere confermata dal
                    // journal (append-only, monotono): il caso v0.12 "log
                    // vuoto + journal non vuoto = incoerente" NON vale qui,
                    // la rotazione è avvenuta legittimamente.
                    let last = journal
                        .read_last(&c.state.genesis.node_vk, &c.state.genesis.genesis_hash)
                        .map_err(|e| LedgerError::TamperDetected {
                            at_record: 0,
                            reason: format!("journal: {}", e),
                        })?;
                    match last {
                        Some((jh, jt)) => {
                            if jh > c.height {
                                return Err(LedgerError::RollbackDetected {
                                    anchor_height: jh,
                                    log_height: c.height,
                                    source: "esterno (journal)",
                                });
                            }
                            if jh < c.height {
                                return Err(LedgerError::TamperDetected {
                                    at_record: 0,
                                    reason:
                                        "journal precedente al checkpoint: violazione di monotonia"
                                            .into(),
                                });
                            }
                            if jt != c.tip_record_hash {
                                return Err(LedgerError::TamperDetected {
                                    at_record: 0,
                                    reason: "tip del checkpoint non corrisponde al journal".into(),
                                });
                            }
                        }
                        None if c.height > 0 => {
                            return Err(LedgerError::TamperDetected {
                                at_record: 0,
                                reason: "journal vuoto con checkpoint a altezza positiva: \
                                         ancore cancellate"
                                    .into(),
                            });
                        }
                        None => {}
                    }
                    (
                        false,
                        c.state.genesis.clone(),
                        Vec::new(),
                        c.tip_record_hash,
                    )
                }
                None => {
                    // Un crash genuino pre-genesis implica journal VUOTO:
                    // le ancore seguono SEMPRE la scrittura del log. Se il
                    // journal contiene già voci, lo stato è incoerente (o
                    // manipolato): rifiuto bloccante.
                    let last = journal
                        .read_last(&node.verification_key, &genesis_hash)
                        .map_err(|e| LedgerError::TamperDetected {
                            at_record: 0,
                            reason: format!("journal: {}", e),
                        })?;
                    if last.is_some() {
                        return Err(LedgerError::TamperDetected {
                            at_record: 0,
                            reason: "log vuoto ma il journal esterno contiene ancore: \
                                     stato incoerente"
                                .into(),
                        });
                    }
                    (
                        true,
                        GenesisRecord::signed(params, node, creator),
                        Vec::new(),
                        genesis_hash,
                    )
                }
            }
        };

        // Verifica di configurazione contro il chiamante (invariata).
        if genesis_rec.genesis_hash != genesis_hash {
            return Err(LedgerError::ConfigMismatch {
                reason: "genesis hash differente dai parametri e dalle identità forniti".into(),
            });
        }
        if genesis_rec.node_vk != node.verification_key {
            return Err(LedgerError::ConfigMismatch {
                reason: "node verification key differente".into(),
            });
        }
        if genesis_rec.creator_vk != creator.verification_key {
            return Err(LedgerError::ConfigMismatch {
                reason: "creator verification key differente".into(),
            });
        }
        if genesis_rec.creator_address != creator.address {
            return Err(LedgerError::ConfigMismatch {
                reason: "creator address differente".into(),
            });
        }
        if address_of(&genesis_rec.creator_vk) != genesis_rec.creator_address {
            return Err(LedgerError::TamperDetected {
                at_record: 0,
                reason: "creator address non deriva dalla creator vk".into(),
            });
        }

        // Collisione creatore/conto di sistema rifiutata: senza questo
        // controllo un conto sovrascriverebbe l'altro al genesis.
        genesis_rec.check_identity_collision()?;

        // Stato iniziale del replay: dal genesis (log pieno) o dal checkpoint
        // (segmento ruotato o recovery a vuoto).
        let mut state = if full_mode {
            LedgerState::new(genesis_rec)
        } else {
            ck.as_ref()
                .expect("segmento ruotato implica checkpoint")
                .state
                .clone()
        };
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
            log_dir: dir.to_path_buf(),
            log_path: log_path.clone(),
            anchor_path,
            ckpt_path,
            journal,
            tip_record_hash: loaded_tip,
            log: None,
            ckpt_every: None,
            last_ckpt_height: ck.as_ref().map(|c| c.height).unwrap_or(0),
            operational: true,
        };
        let log_is_empty = !log_has_records;
        if log_is_empty && ck.is_none() {
            // Log NUOVO (0 byte) o header-only di un'apertura fresh
            // interrotta: riscrittura da zero con TRUNCATE, header e record
            // di genesis.
            ledger.log = Some(open_fresh(&log_path)?);
            let mut head = Vec::new();
            head.extend_from_slice(FILE_MAGIC);
            head.extend_from_slice(&FILE_VERSION.to_le_bytes());
            // write_all sull'handle appena aperto (nessun record pendente).
            let f = ledger.log.as_mut().expect("appena aperto");
            f.write_all(&head)?;
            let g = Record::Genesis(ledger.state.genesis.clone());
            ledger.append_record(node, &g, 0)?;
        } else if log_is_empty {
            // Recovery post-rotazione: log VUOTO o HEADER-ONLY (12 byte è
            // lo stato normale subito dopo una rotazione) SENZA genesis: la
            // catena continua dal checkpoint; ancore risincronizzate.
            // L'append NON riscrive l'header: quello esistente è valido.
            ledger.log = Some(open_append(&log_path)?);
            let c = ck.as_ref().expect("log vuoto con checkpoint");
            ledger.write_anchors(node, c.height, c.tip_record_hash)?;
        } else {
            // Recovery: crash tra log e anchor lascia il log avanti; gli
            // anchor sono risincronizzati alla punta del log verificato.
            let height = ledger.state.height;
            let tip = ledger.tip_record_hash;
            ledger.log = Some(open_append(&log_path)?);
            ledger.write_anchors(node, height, tip)?;
        }
        Ok(ledger)
    }

    /// API pubblica invariata (v0.12): verifica un log pieno che inizia col
    /// record di genesis.
    pub fn read_and_verify_log(
        log_path: &Path,
        anchor_path: &Path,
        journal: &AnchorJournal,
    ) -> Result<(GenesisRecord, Vec<Record>, Hash), LedgerError> {
        let (g, recs, tip) = Self::read_and_verify_log_base(log_path, anchor_path, journal, None)?;
        Ok((
            g.expect("log pieno senza segmentazione contiene il genesis"),
            recs,
            tip,
        ))
    }

    /// Verifica un segmento di log. `ck` (se presente) fornisce la base per i
    /// segmenti ruotati (primo record = blocco, seme = tip del checkpoint)
    /// e il cross-check del checkpoint sui segmenti pieni. Gli anchor sono
    /// validati su ALTEZZE ASSOLUTE: base + offset del segmento.
    fn read_and_verify_log_base(
        log_path: &Path,
        anchor_path: &Path,
        journal: &AnchorJournal,
        ck: Option<&CheckpointView>,
    ) -> Result<(Option<GenesisRecord>, Vec<Record>, Hash), LedgerError> {
        let meta = fs::metadata(log_path)?;
        // Cap PER SEGMENTO (v0.13): la rotazione rende la storia totale non
        // limitata da questo valore.
        if meta.len() > MAX_LOG_BYTES {
            return Err(LedgerError::TamperDetected {
                at_record: 0,
                reason: "segmento di log oltre il limite di dimensione".into(),
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
        let mut node_vk: Option<[u8; VK_SIZE]> = None; // genesis o checkpoint
        let mut is_rotated = false; // deciso al primo record
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
                    if idx == 0 {
                        // Segmento ruotato (v0.13): il primo record è un
                        // blocco; base e identità provengono dal checkpoint
                        // firmato. Senza checkpoint: rifiuto bloccante.
                        let c = ck.ok_or_else(|| LedgerError::TamperDetected {
                            at_record: 0,
                            reason: "segmento di log ruotato senza checkpoint".into(),
                        })?;
                        is_rotated = true;
                        node_vk = Some(c.genesis.node_vk);
                    }
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
            let seed = match prev_hash {
                Some(h) => h,
                None if is_rotated => {
                    ck.expect("segmento ruotato implica checkpoint")
                        .tip_record_hash
                }
                None => match &rec {
                    Record::Genesis(g) => g.genesis_hash,
                    Record::Block(_) => [0u8; HASH_SIZE],
                },
            };
            let h = record_chain_hash(&seed, rec_bytes);
            prev_hash = Some(h);
            chain_hashes.push(h);
            records.push(rec);
            idx += 1;
        }
        if records.is_empty() {
            return Err(LedgerError::TamperDetected {
                at_record: 0,
                reason: "genesis mancante".into(),
            });
        }
        // Base del segmento in ALTEZZE ASSOLUTE.
        let base_height = if is_rotated {
            ck.expect("segmento ruotato implica checkpoint").height
        } else {
            0
        };
        let genesis: GenesisRecord = if is_rotated {
            ck.expect("segmento ruotato implica checkpoint")
                .genesis
                .clone()
        } else {
            if !matches!(records[0], Record::Genesis(_)) {
                return Err(LedgerError::TamperDetected {
                    at_record: 0,
                    reason: "genesis mancante".into(),
                });
            }
            match records.remove(0) {
                Record::Genesis(g) => g,
                _ => unreachable!(),
            }
        };
        // Cross-check del checkpoint sui segmenti PIENI: crash tra scrittura
        // del checkpoint e rotazione lascia il log pieno; la catena al
        // checkpoint deve corrispondere al tip firmato.
        if !is_rotated {
            if let Some(c) = ck {
                let i = c.height as usize;
                if i >= chain_hashes.len() || c.tip_record_hash != chain_hashes[i] {
                    return Err(LedgerError::TamperDetected {
                        at_record: c.height,
                        reason: "catena dei record non corrisponde al checkpoint".into(),
                    });
                }
            }
        }
        let log_height = base_height + records.len() as u64;
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
        if file.payload.height < base_height {
            return Err(LedgerError::TamperDetected {
                at_record: file.payload.height,
                reason: "anchor precedente alla base della catena ricostruibile".into(),
            });
        }
        // Tip atteso: alla base di un segmento ruotato è il tip FIRMATO del
        // checkpoint (crash tra append del log e scrittura dell'anchor);
        // altrove è l'hash di catena del record alla quota dell'anchor
        // (indice assoluto nei segmenti pieni, che includono il genesis in
        // posizione 0; relativo nei segmenti ruotati).
        let expected_local = if file.payload.height == base_height && is_rotated {
            ck.expect("segmento ruotato implica checkpoint")
                .tip_record_hash
        } else {
            let idx = if is_rotated {
                (file.payload.height - base_height - 1) as usize
            } else {
                file.payload.height as usize
            };
            if idx >= chain_hashes.len() {
                return Err(LedgerError::TamperDetected {
                    at_record: file.payload.height,
                    reason: "quota dell'anchor oltre la catena del segmento".into(),
                });
            }
            chain_hashes[idx]
        };
        if file.payload.tip_record_hash != expected_local {
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
        if j_height < base_height {
            return Err(LedgerError::TamperDetected {
                at_record: j_height,
                reason: "journal precedente alla base della catena ricostruibile".into(),
            });
        }
        // Stessa regola del tip atteso dell'anchor locale (base = tip del
        // checkpoint firmato).
        let expected_journal = if j_height == base_height && is_rotated {
            ck.expect("segmento ruotato implica checkpoint")
                .tip_record_hash
        } else {
            let idx = if is_rotated {
                (j_height - base_height - 1) as usize
            } else {
                j_height as usize
            };
            if idx >= chain_hashes.len() {
                return Err(LedgerError::TamperDetected {
                    at_record: j_height,
                    reason: "quota del journal oltre la catena del segmento".into(),
                });
            }
            chain_hashes[idx]
        };
        if j_tip != expected_journal {
            return Err(LedgerError::TamperDetected {
                at_record: j_height,
                reason: "catena dei record non corrisponde al journal esterno".into(),
            });
        }
        Ok((
            if is_rotated { None } else { Some(genesis) },
            records,
            tip_record_hash,
        ))
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
        // Scrittura del record nel segmento corrente. Il borrow del file è
        // confinato in questo blocco: l'anchor viene scritto DOPO, con il
        // borrow mutabile di self già rilasciato.
        let write_result: Result<(), LedgerError> = {
            let f = self.log.as_mut().ok_or(LedgerError::NotOperative)?;
            f.write_all(&len_bytes)?;
            f.write_all(&bytes)?;
            f.sync_all()?;
            Ok(())
        };
        if let Err(e) = write_result {
            self.operational = false;
            return Err(e);
        }
        // Ancore DOPO il record: al riavvio il log può essere al massimo
        // AHEAD delle ancore (crash tra le due scritture) e viene
        // risincronizzato; il contrario (ancore avanti) è impossibile.
        if let Err(e) = self.write_anchors(node, new_height, new_tip) {
            self.operational = false;
            return Err(e);
        }
        self.tip_record_hash = new_tip;
        Ok(())
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

    /// Attiva la rotazione (v0.13): checkpoint firmato + archiviazione del
    /// segmento di log ogni `every_n_blocks` blocchi. Rimuove il limite di
    /// durata del log (il cap MAX_LOG_BYTES diventa per segmento).
    /// `every_n_blocks = 0` disattiva (comportamento v0.12).
    pub fn enable_checkpoints(&mut self, every_n_blocks: u64) {
        self.ckpt_every = if every_n_blocks == 0 {
            None
        } else {
            Some(every_n_blocks)
        };
    }

    /// Scrive ORA un checkpoint firmato e ruota il segmento di log. Ordine
    /// crash-safe: (1) checkpoint atomico e sincronizzato; (2) chiusura
    /// dell'handle del log; (3) rename del log in ledger.log.<height>;
    /// (4) nuovo log con solo header. Un crash in qualunque punto lascia
    /// uno stato riapribile e verificabile (journal + checkpoint).
    pub fn write_checkpoint_now(&mut self, node: &Wallet) -> Result<(), LedgerError> {
        let h = self.state.height;
        let tip = self.tip_record_hash;
        checkpoint::write(&self.ckpt_path, node, &self.state, h, tip)?;
        self.last_ckpt_height = h;
        // Chiusura dell'handle PRIMA dell'archiviazione del segmento.
        self.log = None;
        let archived = self.log_dir.join(format!("ledger.log.{}", h));
        if self.log_path.exists() {
            fs::rename(&self.log_path, &archived)?;
        }
        let mut f = open_append(&self.log_path)?;
        let mut head = Vec::new();
        head.extend_from_slice(FILE_MAGIC);
        head.extend_from_slice(&FILE_VERSION.to_le_bytes());
        f.write_all(&head)?;
        f.sync_all()?;
        self.log = Some(f);
        Ok(())
    }

    fn rotate_if_due(&mut self, node: &Wallet) -> Result<(), LedgerError> {
        let every = match self.ckpt_every {
            Some(e) => e,
            None => return Ok(()),
        };
        if self.state.height >= self.last_ckpt_height.saturating_add(every) {
            self.write_checkpoint_now(node)?;
        }
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
        self.rotate_if_due(node)?;
        Ok(())
    }
}
