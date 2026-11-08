# Amalgam21-A21

Token digitale proprietario post-quantum — prototipo **v0.12**.

Firma ML-DSA-65 (FIPS 204, livello di sicurezza NIST 3) e hash SHAKE256 con output a 512 bit (~2^256 preimage, ~2^170 collision anche contro avversari quantistici). Nessun formato binario è mai cambiato dalla v0.8.

## Struttura del repository

Workspace Cargo a due crate:

| Crate | Contenuto |
| --- | --- |
| `core/` | `token-postquantum`: nucleo (`src/lib.rs`) + demo end-to-end (`src/main.rs`, binario `token-postquantum`) |
| `export/` | `token-postquantum-export`: snapshot JSON dei saldi e indice JSONL dei blocchi per explorer e indexer esterni |

## Compilazione e verifica

```bash
cargo build
cargo test
```

Demo interattiva (la passphrase dei wallet è richiesta con prompt senza eco; la variabile d'ambiente `AMG_PASSPHRASE` è stata eliminata):

```bash
cargo run -p token-postquantum
```

## CI

Il workflow `.github/workflows/rust.yml` esegue `cargo build` e `cargo test` a ogni push e pull request su `main`. Si raccomanda inoltre `cargo audit` (vedi il pin di `libcrux-ml-dsa` in `core/Cargo.toml`).

## Note di sicurezza (estratto)

- Gli hash interni usano SHAKE256-512: preimage ~2^256, collision ~2^170 contro attacchi quantistici (Grover / Brassard-Høyer-Tapp). "Post-quantum" indica primitive senza riduzioni note via Shor/Grover, non sicurezza assoluta.
- `export_hash` e `index_hash` nel crate `export` sono checksum di integrità SHAKE256-512 NON autenticati: la provenienza si attesta solo sul log firmato ML-DSA-65 del core.
- Il journal "esterno" su filesystem locale non fornisce indipendenza reale: l'indipendenza è una proprietà dell'endpoint (WORM/notarizzazione), non del codice.
- Limitazioni dichiarate (checkpoint/rotazione log rimandati a v0.13, mlock, fee sui claim, bridge EVM): vedere gli header dei sorgenti per l'elenco completo.

## Avvertenze

Prototipo a propositore unico, non revisionato con audit indipendente e non adatto a gestire valore reale.
