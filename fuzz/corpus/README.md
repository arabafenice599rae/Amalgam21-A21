# Corpus del fuzzing

Il corpus di input interessanti generati da cargo-fuzz è scritto da libFuzzer
in `fuzz/corpus/<target>/` a runtime e NON è committato (storia del
repository e riproducibilità: il corpus cresce senza limite).

Il corpus minimizzato si rigenera con:

    cargo +nightly fuzz cmin parse_record
    cargo +nightly fuzz cmin parse_block

Per un corpus persistente condiviso tra run, montare `fuzz/corpus/` come
volume esterno o caricarlo come artifact della workflow `fuzz.yml`.
