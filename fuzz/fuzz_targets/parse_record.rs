#![no_main]
// ============================================================================
// FUZZ TARGET: Record (borsh)
// ----------------------------------------------------------------------------
// Invariante: la deserializzazione borsh di Record (Genesis | Block) da
// input ARBITRARIO non deve MAI causare panic, abort o comportamento
// non definito. Il rifiuto pulito (Err) è l'esito corretto per input
// malformati. Esecuzione:
//   cargo +nightly fuzz run parse_record
// ============================================================================

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(rec) = borsh::from_slice::<token_postquantum::Record>(data) {
        // Deserializzato senza panic: il tipo non deve fare nulla di
        // pericoloso alla sola costruzione. Nessuna asserzione sul
        // contenuto: l'invariante è l'assenza di panic.
        let _ = rec;
    }
});
