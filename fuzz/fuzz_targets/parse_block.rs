#![no_main]
// ============================================================================
// FUZZ TARGET: Block e SignedTransaction (borsh)
// ----------------------------------------------------------------------------
// Invariante: la deserializzazione borsh di Block e SignedTransaction da
// input ARBITRARIO non deve MAI causare panic. I campi firmati non vengono
// qui validati (nessuna verifica ML-DSA nel target: il fuzzing copre il
// PARSING, non la crittografia). Esecuzione:
//   cargo +nightly fuzz run parse_block
// ============================================================================

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(b) = borsh::from_slice::<token_postquantum::Block>(data) {
        let _ = b;
    }
    if let Ok(tx) = borsh::from_slice::<token_postquantum::SignedTransaction>(data) {
        let _ = tx;
    }
});
