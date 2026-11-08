# Amalgam21 — Harness di carico

Crate `amg21-stress`: generazione e sottomissione massive di transazioni
firmate ML-DSA-65 contro il ledger reale, con misurazione di TPS, firma,
verifica, RAM di picco, dimensione del log e tempo di riapertura.

## Uso

    cargo run --release -p amg21-stress -- --txs 100000 \
        [--block-size 256] [--wallets 64] [--episode-txs 100000] \
        [--dir /tmp/amg21-stress] [--keep]

Output: una riga JSON per episodio e una riga `summary` con il TPS aggregato.

## Livelli di carico (obiettivi, non misurazioni)

| Livello | Transazioni | Esecuzione prevista |
|---------|-------------|--------------------|
| L1 | 100.000 | Notturna CI (1 episodio) |
| L2 | 1.000.000 | Settimanale CI (10 episodi da 100K) |
| L3 | 10.000.000 | CI a shard paralleli (10 shard da 1M) |
| L4 | 50.000.000 | CI a shard paralleli (50 shard da 1M) |

## Vincoli rispettati

1. `MAX_LOG_BYTES = 1 GiB` (v0.12): oltre il limite il log non è riapribile
   (rotazione differita a v0.13). Il carico è diviso in episodi su directory
   separate; la riapertura è misurata solo sugli episodi sotto soglia.
2. `LedgerState.blocks` vive in RAM (~4 KB per transazione firmata): gli
   episodi da 100K tengono il picco di memoria entro i runner standard.

Per questi vincoli i livelli L2+ misurano la CAPACITÀ DI ELABORAZIONE
(firma, verifica, applicazione, loggatura) e non la crescita di un singolo
ledger oltre il limite dichiarato.
