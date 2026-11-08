// ============================================================================
// AMALGAM21 A21 — TEST DI INTEGRAZIONE: INVARIANTI (T03)
// ----------------------------------------------------------------------------
// Property testing con proptest: dopo una sequenza ARBITRARIA di blocchi
// validi, la conservazione della supply deve valere SEMPRE:
//     somma(saldi) + cashback_pool + airdrop_pool == total_supply
// La verifica è indipendente dal controllo interno accounts_total (riconteggio
// esterno, condotto qui riga per riga sui conti della mappa pubblica).
// Il numero di casi è elevato via PROPCASES (CI: vedi workflows/tests.yml).
// ============================================================================

use proptest::prelude::*;
use std::collections::HashMap;
use token_postquantum::{GenesisParams, Ledger, SignedTransaction, Wallet};

fn seed(i: u64) -> [u8; 32] {
    let mut s = [0u8; 32];
    s[..8].copy_from_slice(&i.to_le_bytes());
    s
}

fn params() -> GenesisParams {
    GenesisParams {
        token_name: "Test".into(),
        symbol: "TST".into(),
        total_supply: 1_000_000,
        domain: "integration-invariants.v1".into(),
        creator_allocation: 599_700,
        fee_pool: 400_000,
        fee: 10,
        cashback_bps: 9_000,
        airdrop_pool: 300,
        airdrop_per_wallet: 100,
        airdrop_max_wallets: 3,
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(
        std::env::var("PROPCASES").ok().and_then(|v| v.parse().ok()).unwrap_or(128)
    ))]

    /// Sequenza casuale di transfer tra creator e 3 wallet reclamati e
    /// finanziati: la supply è conservata dopo OGNI blocco accettato.
    #[test]
    fn supply_conserved_under_random_transfer_sequence(
        base in 0u64..1_000_000,
        ops in prop::collection::vec((0u8..4, 0u8..4, 1u64..50), 1..=16),
    ) {
        let dir = std::env::temp_dir().join(format!("amg21-inv-{}-{}", base, std::process::id()));
        let data = dir.join("data");
        let ext = dir.join("ext");
        std::fs::create_dir_all(&data).unwrap();
        std::fs::create_dir_all(&ext).unwrap();
        let node = Wallet::from_seed(seed(8_000_001 + (base % 1_000)));
        let creator = Wallet::from_seed(seed(8_000_002 + (base % 1_000)));
        let mut l = Ledger::open(&data, &ext, params(), &node, &creator).unwrap();
        let chain = l.state.genesis.genesis_hash;
        // Partecipanti: creator (indice 0) + 3 wallet reclamati e finanziati.
        let wallets: Vec<Wallet> = (0..3u64)
            .map(|i| Wallet::from_seed(seed(8_100_000 + base * 10 + i)))
            .collect();
        let mut funding: Vec<SignedTransaction> = Vec::new();
        for w in &wallets {
            funding.push(SignedTransaction::claim(w, chain, 0));
        }
        l.submit(&node, funding).unwrap();
        let mut nonce_creator = 0u64;
        let mut transfers: Vec<SignedTransaction> = Vec::new();
        for w in &wallets {
            transfers.push(SignedTransaction::transfer(
                &creator, chain, nonce_creator, w.address, 1000,
            ));
            nonce_creator += 1;
        }
        l.submit(&node, transfers).unwrap();

        let mut nonces: HashMap<u8, u64> = HashMap::new();
        nonces.insert(0, nonce_creator);
        for (i, w) in wallets.iter().enumerate() {
            nonces.insert(i as u8 + 1, l.state.nonce(&w.address));
        }

        for (s, r, amount) in ops {
            let (s, r) = (s % 4, r % 4);
            if s == r {
                continue;
            }
            let sender = if s == 0 { &creator } else { &wallets[(s - 1) as usize] };
            let recipient = if r == 0 { creator.address } else { wallets[(r - 1) as usize].address };
            let n = nonces.get_mut(&s).expect("nonce noto");
            let tx = SignedTransaction::transfer(sender, chain, *n, recipient, amount);
            *n += 1;
            l.submit(&node, vec![tx]).unwrap();

            // INVARIANTE indipendente: riconteggio esterno della supply.
            let sum: u128 = l
                .state
                .accounts
                .values()
                .map(|a| a.balance as u128)
                .sum();
            prop_assert_eq!(
                sum + l.state.cashback_pool as u128 + l.state.airdrop_pool as u128,
                l.state.genesis.params.total_supply as u128
            );
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
}
