// ============================================================================
// AMALGAM21 A21 — HARNESS DI CARICO (stress/src/main.rs)
// ----------------------------------------------------------------------------
// Genera e sottomette milioni di transazioni firmate ML-DSA-65, misurando:
//   - transazioni al secondo (firmate + verificate + applicate + loggate);
//   - tempo totale, tempo di firma e tempo di submit;
//   - RAM di picco (VmHWM da /proc/self/status su Linux);
//   - dimensione del log firmato;
//   - tempo di riapertura e verifica integrale del ledger.
//
// LIVELLI DI CARICO (obiettivi dichiarati, NON misurati):
//   L1  100.000 tx     — notturna CI (una sessione, ~400 MB di log)
//   L2  1.000.000 tx   — settimanale CI (10 episodi da 100K)
//   L3  10.000.000 tx  — CI a shard paralleli (10 shard da 1M)
//   L4  50.000.000 tx  — CI a shard paralleli (50 shard da 1M; richiede
//                        runner ampio o self-hosted per il tempo totale)
//
// VINCOLI FISICI RISPETTATI DALL'HARNESS (per documentazione v0.12 del core):
//   1. MAX_LOG_BYTES = 1 GiB: oltre il limite il log NON è riapribile
//      (rotazione differita a v0.13). Per questo il carico è diviso in
//      EPISODI su directory separate: ogni episodio resta sotto il limite
//      e la riapertura è misurata solo sull'episodio che resta sotto soglia.
//   2. LedgerState.blocks è interamente in RAM (~4 KB per tx): gli episodi
//      mantengono il picco di memoria compatibile con i runner standard.
//
// Uso:
//   cargo run --release -p amg21-stress -- --txs 100000 \
//       [--block-size 256] [--wallets 64] [--episode-txs 100000] \
//       [--dir /tmp/amg21-stress] [--keep]
// L'output è una riga JSON per episodio più una riga di riepilogo.
// ============================================================================

use std::path::PathBuf;
use std::time::{Duration, Instant};
use token_postquantum::{GenesisParams, Ledger, SignedTransaction, Wallet};

struct Args {
    txs: u64,
    block_size: usize,
    wallets: usize,
    episode_txs: u64,
    dir: PathBuf,
    keep: bool,
}

fn parse_args() -> Args {
    let mut a = Args {
        txs: 100_000,
        block_size: 256,
        wallets: 64,
        episode_txs: 100_000,
        dir: std::env::temp_dir().join("amg21-stress"),
        keep: false,
    };
    let mut it = std::env::args().skip(1);
    while let Some(k) = it.next() {
        let mut v = || it.next().expect("parametro senza valore");
        match k.as_str() {
            "--txs" => a.txs = v().parse().expect("--txs numerico"),
            "--block-size" => a.block_size = v().parse().expect("--block-size numerico"),
            "--wallets" => a.wallets = v().parse().expect("--wallets numerico"),
            "--episode-txs" => a.episode_txs = v().parse().expect("--episode-txs numerico"),
            "--dir" => a.dir = PathBuf::from(v()),
            "--keep" => a.keep = true,
            other => panic!("parametro sconosciuto: {}", other),
        }
    }
    a.block_size = a.block_size.min(1024); // MAX_TXS_PER_BLOCK del core
    a
}

fn seed(i: u64) -> [u8; 32] {
    let mut s = [0u8; 32];
    s[..8].copy_from_slice(&i.to_le_bytes());
    s
}

fn peak_rss_mb() -> f64 {
    let status = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("VmHWM:") {
            let kb: f64 = rest
                .trim()
                .trim_end_matches("kB")
                .trim()
                .parse()
                .unwrap_or(0.0);
            return kb / 1024.0;
        }
    }
    0.0
}

struct EpisodeStats {
    episode: u64,
    txs: u64,
    blocks: u64,
    sign: Duration,
    submit: Duration,
    total: Duration,
    log_mb: f64,
    reopen_ms: f64,
    peak_rss_mb: f64,
}

fn episode_economics(transfer_txs: u64, wallets: usize) -> (GenesisParams, u64) {
    const AMOUNT: u64 = 1;
    const FEE: u64 = 1;
    let per_wallet = (transfer_txs / wallets as u64) * (AMOUNT + FEE) + 10_000;
    let creator_allocation = per_wallet * wallets as u64 + 100_000;
    let params = GenesisParams {
        token_name: "Amalgam21 Stress".into(),
        symbol: "A21".into(),
        total_supply: creator_allocation,
        domain: "stress.v1".into(),
        creator_allocation,
        fee_pool: 0,
        fee: FEE,
        cashback_bps: 0,
        airdrop_pool: 0,
        airdrop_per_wallet: 0,
        airdrop_max_wallets: 0,
    };
    (params, per_wallet)
}

fn run_episode(args: &Args, episode: u64, txs: u64) -> EpisodeStats {
    let base = args.dir.join(format!("ep{:#06}", episode));
    let data = base.join("data");
    let ext = base.join("ext");
    let _ = std::fs::remove_dir_all(&base);
    std::fs::create_dir_all(&data).expect("creazione data");
    std::fs::create_dir_all(&ext).expect("creazione ext");

    let node = Wallet::from_seed(seed(0xF00D));
    let creator = Wallet::from_seed(seed(0xBEEF));
    let wallets: Vec<Wallet> = (0..args.wallets)
        .map(|i| Wallet::from_seed(seed(0x1000 + i as u64)))
        .collect();
    let (params, per_wallet) = episode_economics(txs, args.wallets);

    let t0 = Instant::now();
    let mut l = Ledger::open(&data, &ext, params.clone(), &node, &creator)
        .expect("apertura ledger dell'episodio");
    let chain = l.state.genesis.genesis_hash;

    // Fase 1: funding di tutti i wallet da parte del creator (un blocco).
    let mut sign = Duration::ZERO;
    let mut submit = Duration::ZERO;
    let t = Instant::now();
    let mut funding = Vec::with_capacity(wallets.len());
    for (i, w) in wallets.iter().enumerate() {
        funding.push(SignedTransaction::transfer(
            &creator, chain, i as u64, w.address, per_wallet,
        ));
    }
    sign += t.elapsed();
    let t = Instant::now();
    l.submit(&node, funding).expect("blocco di funding");
    submit += t.elapsed();

    // Fase 2: claim di tutti i wallet (un blocco).
    let t = Instant::now();
    let claims: Vec<SignedTransaction> = wallets
        .iter()
        .map(|w| SignedTransaction::claim(w, chain, 0))
        .collect();
    sign += t.elapsed();
    let t = Instant::now();
    l.submit(&node, claims).expect("blocco di claim");
    submit += t.elapsed();

    // Fase 3: transfer massivi a rotazione tra i wallet.
    let mut nonces = vec![1u64; wallets.len()];
    let mut blocks = 2u64;
    let mut done = 0u64;
    while done < txs {
        let n = (txs - done).min(args.block_size as u64);
        let t = Instant::now();
        let mut batch = Vec::with_capacity(n as usize);
        for k in 0..n {
            let s = (done + k) as usize % wallets.len();
            let to = wallets[(s + 1) % wallets.len()].address;
            batch.push(SignedTransaction::transfer(
                &wallets[s],
                chain,
                nonces[s],
                to,
                1,
            ));
            nonces[s] += 1;
        }
        sign += t.elapsed();
        let t = Instant::now();
        l.submit(&node, batch).expect("blocco di transfer");
        submit += t.elapsed();
        done += n;
        blocks += 1;
    }

    let total = t0.elapsed();
    let log_bytes = std::fs::metadata(data.join("ledger.log"))
        .map(|m| m.len())
        .unwrap_or(0);
    let log_mb = log_bytes as f64 / 1024.0 / 1024.0;

    // Riapertura SOLO se il log resta sotto il limite MAX_LOG_BYTES (1 GiB):
    // oltre il limite la riapertura è correttamente rifiutata (v0.13: rotazione).
    let mut reopen_ms = -1.0f64;
    if log_bytes < 900 * 1024 * 1024 {
        drop(l);
        let t = Instant::now();
        let l2 = Ledger::open(&data, &ext, params.clone(), &node, &creator)
            .expect("riapertura dell'episodio sotto il limite");
        reopen_ms = t.elapsed().as_secs_f64() * 1000.0;
        assert_eq!(l2.state.height, blocks, "altezza ricostruita");
    } else {
        drop(l);
    }

    if !args.keep {
        let _ = std::fs::remove_dir_all(&base);
    }

    EpisodeStats {
        episode,
        txs,
        blocks,
        sign,
        submit,
        total,
        log_mb,
        reopen_ms,
        peak_rss_mb: peak_rss_mb(),
    }
}

fn main() {
    let args = parse_args();
    println!(
        "{{\"phase\":\"config\",\"txs\":{},\"block_size\":{},\"wallets\":{},\"episode_txs\":{}}}",
        args.txs, args.block_size, args.wallets, args.episode_txs
    );
    let episodes = args.txs.div_ceil(args.episode_txs);
    let mut grand_txs = 0u64;
    let mut grand_ns = 0u128;
    for e in 0..episodes {
        let n = args.episode_txs.min(args.txs - grand_txs);
        let st = run_episode(&args, e, n);
        grand_txs += st.txs;
        grand_ns += st.total.as_nanos();
        println!(
            "{{\"episode\":{},\"txs\":{},\"blocks\":{},\"sign_ms\":{:.0},\"submit_ms\":{:.0},\"total_ms\":{:.0},\"log_mb\":{:.1},\"reopen_ms\":{:.0},\"peak_rss_mb\":{:.0}}}",
            st.episode,
            st.txs,
            st.blocks,
            st.sign.as_secs_f64() * 1000.0,
            st.submit.as_secs_f64() * 1000.0,
            st.total.as_secs_f64() * 1000.0,
            st.log_mb,
            st.reopen_ms,
            st.peak_rss_mb
        );
    }
    let tps = grand_txs as f64 / (grand_ns as f64 / 1e9);
    println!(
        "{{\"summary\":\"done\",\"episodes\":{},\"txs\":{},\"tps\":{:.0},\"peak_rss_mb\":{:.0}}}",
        episodes,
        grand_txs,
        tps,
        peak_rss_mb()
    );
}
