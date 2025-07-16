//! An AIR for the Blake-3 permutation. Assumes the field size is between 2^20 and 2^32.

// #![no_std]

extern crate alloc;

mod air;
mod columns;
mod constants;
mod generation;

pub use air::*;
pub use columns::*;
pub use generation::*;

#[cfg(test)]
mod tests {
    use crate::Blake3Air;
    use p3_baby_bear::{BabyBear, BabyBearParameters};
    use p3_challenger::{HashChallenger, SerializingChallenger32, SerializingChallenger64};
    use p3_commit::ExtensionMmcs;
    use p3_dft::Radix2DitParallel;
    use p3_field::extension::BinomialExtensionField;
    use p3_fri::{TwoAdicFriPcs, create_benchmark_fri_params};
    use p3_goldilocks::Goldilocks;
    use p3_keccak::{Keccak256Hash, KeccakF};
    use p3_merkle_tree::MerkleTreeMmcs;
    use p3_monty_31::MontyField31;
    use p3_monty_31::dft::RecursiveDft;
    use p3_symmetric::{CompressionFunctionFromHasher, PaddingFreeSponge, SerializingHasher};
    use p3_uni_stark::{StarkConfig, prove, verify};

    type Sponge = PaddingFreeSponge<KeccakF, 25, 17, 4>; // Poseidon2 is also possible
    type KeccakCompressionFunction = CompressionFunctionFromHasher<Sponge, 2, 4>;

    const KECCAK_VECTOR_LEN: usize = p3_keccak::VECTOR_LEN;
    const LOG_TRACE_LENGTH: usize = 0;

    #[test]
    fn test_blake3_proving_goldilocks() {
        type F = Goldilocks;
        type EF = BinomialExtensionField<F, 2>;

        let trace_height: usize = 1 << LOG_TRACE_LENGTH;
        let proof_goal = Blake3Air {};

        let dft = Radix2DitParallel::<Goldilocks>::default();
        let u64_hash = Sponge::new(KeccakF {});
        let field_hash = SerializingHasher::new(u64_hash);
        let compress = KeccakCompressionFunction::new(u64_hash);
        let val_mmcs = MerkleTreeMmcs::<
            [F; KECCAK_VECTOR_LEN],
            [u64; KECCAK_VECTOR_LEN],
            SerializingHasher<Sponge>,
            KeccakCompressionFunction,
            4,
        >::new(field_hash, compress);

        let challenge_mmcs = ExtensionMmcs::<F, EF, _>::new(val_mmcs.clone());

        let fri_params = create_benchmark_fri_params(challenge_mmcs);

        let trace = proof_goal.generate_trace_rows::<F>(trace_height, fri_params.log_blowup);

        let pcs = TwoAdicFriPcs::<F, _, _, _>::new(dft, val_mmcs, fri_params);

        let challenger = SerializingChallenger64::from_hasher(vec![], Keccak256Hash {});

        let stark_config = StarkConfig::<
            _,
            EF,
            SerializingChallenger64<Goldilocks, HashChallenger<u8, Keccak256Hash, 32>>,
        >::new(pcs, challenger);

        let proof = prove(&stark_config, &proof_goal, trace, &vec![]);

        let config = bincode::config::standard()
            .with_little_endian()
            .with_fixed_int_encoding();
        let proof_bytes =
            bincode::serde::encode_to_vec(&proof, config).expect("Failed to serialize proof");
        println!("Proof size: {} bytes", proof_bytes.len());

        verify(&stark_config, &proof_goal, &proof, &vec![]).expect("verification issue");
    }

    #[test]
    fn test_blake3_proving() {
        type F = BabyBear; // KoalaBear is also possible
        type EF = BinomialExtensionField<F, 4>;

        // every compression/permutation occupies exactly one row in the RowMajorMatrix, so trace_height is actually a number of permutations that we prove
        let trace_height: usize = 1 << LOG_TRACE_LENGTH;

        let proof_goal = Blake3Air {};

        let dft = RecursiveDft::<MontyField31<BabyBearParameters>>::new(trace_height << 1); // RadixTwoDitParallel is also possible

        let u64_hash = Sponge::new(KeccakF {});

        let field_hash = SerializingHasher::new(u64_hash);

        let compress = KeccakCompressionFunction::new(u64_hash);

        let val_mmcs = MerkleTreeMmcs::<
            [F; KECCAK_VECTOR_LEN],
            [u64; KECCAK_VECTOR_LEN],
            SerializingHasher<Sponge>,
            KeccakCompressionFunction,
            4,
        >::new(field_hash, compress);

        let challenge_mmcs = ExtensionMmcs::<F, EF, _>::new(val_mmcs.clone());

        let fri_params = create_benchmark_fri_params(challenge_mmcs);

        let trace = proof_goal.generate_trace_rows::<MontyField31<BabyBearParameters>>(
            trace_height,
            fri_params.log_blowup,
        );
        // println!("trace: {:02x?}", trace);

        let pcs = TwoAdicFriPcs::<BabyBear, _, _, _>::new(dft, val_mmcs, fri_params);

        let challenger = SerializingChallenger32::from_hasher(vec![], Keccak256Hash {});

        let stark_config = StarkConfig::<
            _,
            EF,
            SerializingChallenger32<F, HashChallenger<u8, Keccak256Hash, 32>>,
        >::new(pcs, challenger);

        let proof = prove(&stark_config, &proof_goal, trace, &vec![]);

        let config = bincode::config::standard()
            .with_little_endian()
            .with_fixed_int_encoding();
        let proof_bytes =
            bincode::serde::encode_to_vec(&proof, config).expect("Failed to serialize proof");
        println!("Proof size: {} bytes", proof_bytes.len());

        verify(&stark_config, &proof_goal, &proof, &vec![]).expect("verification issue");
    }
}
