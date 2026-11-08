// ============================================================================
// core/src/types.rs — Parametri genesis, transazioni firmate, blocchi,
// record del log: i tipi serializzati che definiscono i formati binari.
// ============================================================================

use crate::*;

use borsh::{BorshDeserialize, BorshSerialize};

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
// Transazioni: Transfer e Claim, entrambe firmate ML-DSA-65 dal mittente
// ---------------------------------------------------------------------------
#[derive(BorshSerialize, BorshDeserialize, Clone, Debug)]
// La variante Claim contiene una vk ML-DSA-65 (1952 byte): il boxing cambierebbe
// la semantica di copia del tipo; dimensioni accettate per stabilita' del formato.
#[allow(clippy::large_enum_variant)]
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

    pub(crate) fn canonical_bytes(&self) -> Vec<u8> {
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
    pub(crate) fn build(
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
    pub(crate) fn verify(&self, node_vk: &[u8; VK_SIZE]) -> bool {
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
    pub(crate) fn canonical_bytes(&self) -> Vec<u8> {
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

    pub(crate) fn signed(params: GenesisParams, node: &Wallet, creator: &Wallet) -> Self {
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

    pub(crate) fn verify_signature(&self) -> bool {
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
    pub(crate) fn check_identity_collision(&self) -> Result<(), LedgerError> {
        if self.creator_address == address_of(&self.node_vk) {
            return Err(LedgerError::ConfigMismatch {
                reason: "l'indirizzo del creatore coincide con il conto di sistema (derivato dalla chiave del nodo)".into(),
            });
        }
        Ok(())
    }
}

#[derive(BorshSerialize, BorshDeserialize, Clone, Debug)]
// GenesisRecord e' intenzionalmente inline: il boxing non e' applicato per non
// alterare la semantica del tipo; dimensioni accettate.
#[allow(clippy::large_enum_variant)]
pub enum Record {
    Genesis(GenesisRecord),
    Block(Block),
}
