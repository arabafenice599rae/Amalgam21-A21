// ============================================================================
// core/src/state.rs — Stato contabile: applicazione IN PLACE con undo log,
// invariante incrementale di supply, facciata di lettura ERC-20-like.
// ============================================================================

use crate::*;

use std::collections::HashMap;

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
    pub(crate) fn new(genesis: GenesisRecord) -> Self {
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
    /// conti nell'ordine inverso dello snapshot, totale contabile, pool
    /// cashback e pool airdrop ripristinati.
    fn rollback(
        &mut self,
        undo: Vec<(Address, Option<Account>)>,
        old_total: u128,
        old_cashback: u64,
        old_airdrop: u64,
    ) {
        self.accounts_total = old_total;
        self.cashback_pool = old_cashback;
        self.airdrop_pool = old_airdrop;
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
        let chunk = n.div_ceil(threads);
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

        // CORREZIONE DI SICUREZZA (Claim→Transfer nello stesso blocco): la
        // pre-verifica RINVIA i Transfer da mittenti esistenti ma NON ancora
        // reclamati (vk registrata azzerata, firma non verificabile lì). Se
        // un Claim precedente nello STESSO blocco registra la vk, un
        // Transfer successivo di quel mittente non è mai stato verificato
        // da nessuno. Qui si registra l'insieme dei mittenti rinviati; il
        // ramo Transfer del ciclo sequenziale verifica la firma contro la
        // vk registrata a quel punto (appena associata dal Claim) prima di
        // ogni mutazione. Senza questo controllo, un Transfer contraffatto
        // da un conto reclamato nello stesso blocco sarebbe accettato.
        let deferred: std::collections::HashSet<Address> = h
            .txs
            .iter()
            .filter_map(|tx| match &tx.core.action {
                TxAction::Transfer { .. } => match self.accounts.get(&tx.core.from) {
                    Some(a) if !a.claimed => Some(tx.core.from),
                    _ => None,
                },
                _ => None,
            })
            .collect();

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
        let old_cashback = self.cashback_pool;
        let old_airdrop = self.airdrop_pool;

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
                        // Firma DIFFERITA: mittente non reclamato a inizio
                        // blocco (pre-verifica rinviata) e reclamato da un
                        // Claim precedente nello stesso blocco. La firma va
                        // verificata ORA contro la vk appena registrata:
                        // è l'unica occasione in cui la vk di questo conto
                        // è nota e la firma non è ancora stata controllata.
                        if deferred.contains(&tx.core.from)
                            && !verify_signature(
                                &sender.verification_key,
                                &tx.canonical_bytes(),
                                TX_CONTEXT,
                                &tx.signature,
                            )
                        {
                            return Err(LedgerError::InvalidSignature);
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
            self.rollback(undo, old_total, old_cashback, old_airdrop);
            return Err(e);
        }

        // Invariante di supply INCREMENTALE (v0.12): O(1) per blocco.
        let total = self
            .accounts_total
            .checked_add(self.cashback_pool as u128)
            .and_then(|t| t.checked_add(self.airdrop_pool as u128))
            .ok_or(LedgerError::Overflow)?;
        if total != supply {
            self.rollback(undo, old_total, old_cashback, old_airdrop);
            return Err(LedgerError::SupplyInvariantBroken);
        }

        self.height = block.header.height;
        self.tip_block_hash = block.block_hash;
        self.blocks.push(block.clone());
        Ok(())
    }
}

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
