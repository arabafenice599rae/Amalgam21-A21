# Amalgam21 Token (A21)

Token digitale proprietario post-quantum: firme ML-DSA-65 (FIPS 204, livello 3 NIST),
hash SHAKE256 a 512 bit, ledger autoritario a firmatario unico, wallet non-custodial
(Argon2id + XChaCha20-Poly1305).

## Struttura del workspace

- core/ — crate token-postquantum: nucleo del ledger (formati, wallet, conti, blocchi,
  anchor, journal, facciata ERC-20-like) e demo end-to-end.
- export/ — crate token-postquantum-export: snapshot JSON dei saldi e indice JSONL
  dei blocchi per explorer e indexer; vista derivata, non autoritativa.

## Comandi

    cargo build --workspace
    cargo test --workspace
    cargo run -p token-postquantum   # demo interattiva (passphrase via prompt)

## CI (GitHub Actions)

A ogni push e pull request: cargo fmt --check, cargo clippy -D warnings, build, test
e cargo audit (vulnerabilita' note delle dipendenze). I controlli sono job separati:
il fallimento di uno non nasconde gli esiti degli altri.

## Modello dichiarato

- Supply 100M token, 6 decimali; importi in unita' intere u64, mai virgola mobile.
- Fee fissa, intera, al conto di sistema; cashback 90% dal pool dedicato.
- Nessun formato binario cambia dalla v0.8.
- Dichiarazioni di sicurezza e limitazioni: intestazioni dei sorgenti.

## Licenza

Copyright Amalgam21. Tutti i diritti riservati. Nessuna licenza d'uso concessa.
