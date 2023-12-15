use core::marker::PhantomData;

use plonky2::field::extension::Extendable;
use plonky2::field::secp256k1_scalar::Secp256K1Scalar;
use plonky2::field::types::PrimeField;
use plonky2::gadgets::arithmetic::EqualityGenerator;
use plonky2::gadgets::split_base::BaseSumGenerator;
use plonky2::gates::arithmetic_base::{ArithmeticBaseGenerator, ArithmeticGate};
use plonky2::gates::arithmetic_extension::ArithmeticExtensionGate;
use plonky2::gates::base_sum::{BaseSplitGenerator, BaseSumGate};
use plonky2::gates::constant::ConstantGate;
use plonky2::gates::coset_interpolation::CosetInterpolationGate;
use plonky2::gates::exponentiation::ExponentiationGate;
use plonky2::gates::lookup::LookupGate;
use plonky2::gates::lookup_table::LookupTableGate;
use plonky2::gates::multiplication_extension::MulExtensionGate;
use plonky2::gates::noop::NoopGate;
use plonky2::gates::poseidon::{PoseidonGate, PoseidonGenerator};
use plonky2::gates::poseidon2::{Poseidon2Gate, Poseidon2Generator};
use plonky2::gates::poseidon_mds::{PoseidonMdsGate, PoseidonMdsGenerator};
use plonky2::gates::public_input::PublicInputGate;
use plonky2::gates::random_access::{RandomAccessGate, RandomAccessGenerator};
use plonky2::gates::reducing::ReducingGate;
use plonky2::gates::reducing_extension::ReducingExtensionGate;
use plonky2::hash::hash_types::RichField;
use plonky2::iop::generator::{ConstantGenerator, RandomValueGenerator};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::config::{AlgebraicHasher, GenericConfig};
use plonky2::recursion::dummy_circuit::DummyProofGenerator;
use plonky2::util::serialization::{GateSerializer, WitnessGeneratorSerializer};
use plonky2_u32::gates::add_many_u32::{U32AddManyGate, U32AddManyGenerator};
use plonky2_u32::gates::arithmetic_u32::{U32ArithmeticGate, U32ArithmeticGenerator};
use plonky2_u32::gates::comparison::{ComparisonGate, ComparisonGenerator};
use plonky2_u32::gates::range_check_u32::{U32RangeCheckGate, U32RangeCheckGenerator};
use plonky2_u32::gates::subtraction_u32::{U32SubtractionGate, U32SubtractionGenerator};

use crate::ecdsa::curve::curve_types::Curve;
use crate::ecdsa::curve::secp256k1::Secp256K1;
use crate::ecdsa::gadgets::curve::{AffinePointTarget, CircuitBuilderCurve};
use crate::ecdsa::gadgets::curve_fixed_base::fixed_base_curve_mul_circuit;
use crate::ecdsa::gadgets::glv::CircuitBuilderGlv;
use crate::ecdsa::gadgets::nonnative::{CircuitBuilderNonNative, NonNativeTarget};
use plonky2::{
    get_gate_tag_impl, get_generator_tag_impl, impl_gate_serializer, impl_generator_serializer,
    read_gate_impl, read_generator_impl,
};

use super::glv::GLVDecompositionGenerator;
use super::nonnative::{
    NonNativeAdditionGenerator, NonNativeInverseGenerator, NonNativeMultiplicationGenerator,
    NonNativeSubtractionGenerator,
};

use ethers_core::utils::keccak256;
#[derive(Clone, Debug)]
pub struct ECDSASecretKeyTarget<C: Curve>(pub NonNativeTarget<C::ScalarField>);

#[derive(Clone, Debug)]
pub struct ECDSAPublicKeyTarget<C: Curve>(pub AffinePointTarget<C>);

#[derive(Clone, Debug)]
pub struct ECDSASignatureTarget<C: Curve> {
    pub r: NonNativeTarget<C::ScalarField>,
    pub s: NonNativeTarget<C::ScalarField>,
}

pub struct CustomGateSerializer;

impl<F: RichField + Extendable<D>, const D: usize> GateSerializer<F, D> for CustomGateSerializer {
    impl_gate_serializer! {
        DefaultGateSerializer,
        ArithmeticGate,
        ArithmeticExtensionGate<D>,
        BaseSumGate<4>,
        ConstantGate,
        CosetInterpolationGate<F, D>,
        ComparisonGate<F, D>,
        ExponentiationGate<F, D>,
        LookupGate,
        LookupTableGate,
        MulExtensionGate<D>,
        NoopGate,
        // PoseidonMdsGate<F, D>,
        // PoseidonGate<F, D>,
        Poseidon2Gate<F, D>,
        PublicInputGate,
        RandomAccessGate<F, D>,
        ReducingExtensionGate<D>,
        ReducingGate<D>,
        U32AddManyGate<F, D>,
        U32ArithmeticGate<F, D>,
        U32RangeCheckGate<F, D>,
        U32SubtractionGate<F, D>
    }
}

pub struct CustomGeneratorSerializer<C: GenericConfig<D>, FF: PrimeField, const D: usize> {
    pub _phantom: PhantomData<C>,
    pub _phantom2: PhantomData<FF>,
}

impl<F, FF, C, const D: usize> WitnessGeneratorSerializer<F, D>
    for CustomGeneratorSerializer<C, FF, D>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F> + 'static,
    C::Hasher: AlgebraicHasher<F>,
    FF: PrimeField,
{
    impl_generator_serializer! {
        // CustomGeneratorSerializer,
        DummyProofGenerator<F, C, D>,
        ArithmeticBaseGenerator<F, D>,
        ConstantGenerator<F>,
        // PoseidonGenerator<F, D>,
        // PoseidonMdsGenerator<D>,
        Poseidon2Generator<F, D>,
        RandomValueGenerator,
        BaseSumGenerator<4>,
        NonNativeMultiplicationGenerator<F, D, FF>,
        NonNativeAdditionGenerator<F, D, FF>,
        NonNativeInverseGenerator<F, D, FF>,
        NonNativeSubtractionGenerator<F, D, FF>,
        GLVDecompositionGenerator<F, D>,
        U32RangeCheckGenerator<F, D>,
        EqualityGenerator,
        U32ArithmeticGenerator<F, D>,
        U32AddManyGenerator<F, D>,
        ComparisonGenerator<F,D>,
        BaseSplitGenerator<2>,
        RandomAccessGenerator<F, D>,
        U32SubtractionGenerator<F, D>
    }
}

pub fn verify_message_circuit<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    msg: NonNativeTarget<Secp256K1Scalar>,
    sig: ECDSASignatureTarget<Secp256K1>,
    pk: ECDSAPublicKeyTarget<Secp256K1>,
) {
    let ECDSASignatureTarget { r, s } = sig;

    builder.curve_assert_valid(&pk.0);

    let c = builder.inv_nonnative(&s);
    let u1 = builder.mul_nonnative(&msg, &c);
    let u2 = builder.mul_nonnative(&r, &c);

    let point1 = fixed_base_curve_mul_circuit(builder, Secp256K1::GENERATOR_AFFINE, &u1);
    let point2 = builder.glv_mul(&pk.0, &u2);
    let point = builder.curve_add(&point1, &point2);

    let x = NonNativeTarget::<Secp256K1Scalar> {
        value: point.x.value,
        _phantom: PhantomData,
    };
    builder.connect_nonnative(&r, &x);
}

pub fn batch_verify_message_circuit<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    msgs: Vec<NonNativeTarget<Secp256K1Scalar>>,
    sigs: Vec<ECDSASignatureTarget<Secp256K1>>,
    pks: Vec<ECDSAPublicKeyTarget<Secp256K1>>,
) {
    assert_eq!(msgs.len(), sigs.len());
    assert_eq!(msgs.len(), pks.len());

    for ((msg, sig), pk) in msgs.into_iter().zip(sigs.into_iter()).zip(pks.into_iter()) {
        let ECDSASignatureTarget { r, s } = sig;

        builder.curve_assert_valid(&pk.0);

        let c = builder.inv_nonnative(&s);
        let u1 = builder.mul_nonnative(&msg, &c);
        let u2 = builder.mul_nonnative(&r, &c);

        let point1 = fixed_base_curve_mul_circuit(builder, Secp256K1::GENERATOR_AFFINE, &u1);
        let point2 = builder.glv_mul(&pk.0, &u2);
        let point = builder.curve_add(&point1, &point2);

        let x = NonNativeTarget::<Secp256K1Scalar> {
            value: point.x.value,
            _phantom: PhantomData,
        };
        builder.connect_nonnative(&r, &x);
    }
}

#[cfg(test)]
mod tests {
    use std::fs::{self, File};
    use std::io::prelude::*;
    use std::io::{BufReader, Write};

    use crate::ecdsa::curve::secp256k1;
    use crate::ecdsa::gadgets::biguint::{BigUintTarget, WitnessBigUint};
    use crate::hash::keccak256;
    use anyhow::{Ok, Result};
    use log::Level;
    use plonky2::field::goldilocks_field::GoldilocksField;
    use plonky2::field::types::{PrimeField, Sample};
    use plonky2::hash::hash_types::HashOut;
    use plonky2::hash::hashing::hash_n_to_hash_no_pad;
    use plonky2::hash::poseidon::PoseidonPermutation;
    use plonky2::iop::target::Target;
    use plonky2::iop::witness::{PartialWitness, WitnessWrite};
    use plonky2::plonk::circuit_data::{
        CircuitConfig, CircuitData, CommonCircuitData, VerifierCircuitTarget,
        VerifierOnlyCircuitData,
    };
    use plonky2::plonk::config::{
        GenericConfig, GenericHashOut, Poseidon2GoldilocksConfig, PoseidonGoldilocksConfig,
    };
    use plonky2::plonk::proof::ProofWithPublicInputs;
    use plonky2::plonk::prover::prove;
    use plonky2::util::serialization::{DefaultGateSerializer, DefaultGeneratorSerializer};
    use plonky2::util::timing::TimingTree;
    use sha3::Sha3_256;

    use super::*;
    use crate::ecdsa::curve::curve_types::CurveScalar;
    use crate::ecdsa::curve::ecdsa::{
        sign_message, ECDSAPublicKey, ECDSASecretKey, ECDSASignature,
    };
    use crate::profiling_enable;
    use plonky2::field::types::Field;

    use plonky2::recursion::tree_recursion::{
        check_tree_proof_verifier_data, common_data_for_recursion,
        set_tree_recursion_leaf_data_target, set_tree_recursion_node_data_target,
        TreeRecursionLeafData, TreeRecursionNodeData,
    };

    fn test_tree_recursion_with_ecdsa_circuit(config: CircuitConfig) -> Result<()> {
        profiling_enable();
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;

        type Curve = Secp256K1;

        let mut builder = CircuitBuilder::<F, D>::new(config);

        let msg_target = builder.add_virtual_nonnative_target();
        let msg_biguint_target = builder.nonnative_to_canonical_biguint(&msg_target);

        // let pk_target = ECDSAPublicKeyTarget(builder.constant_affine_point(pk.0));
        // TODO: builder.constant_affine_point(pk.0) has an extra debug_assert!(!point.zero);
        let pk_target = ECDSAPublicKeyTarget(builder.add_virtual_affine_point_target());
        let pk_x_biguint_target = builder.nonnative_to_canonical_biguint(&pk_target.0.x);
        let pk_y_biguint_target = builder.nonnative_to_canonical_biguint(&pk_target.0.y);

        let r_target = builder.add_virtual_nonnative_target();
        let r_biguint_target = builder.nonnative_to_canonical_biguint(&r_target);

        let s_target = builder.add_virtual_nonnative_target();
        let s_biguint_target = builder.nonnative_to_canonical_biguint(&s_target);

        let sig_target = ECDSASignatureTarget {
            r: r_target,
            s: s_target,
        };

        verify_message_circuit(&mut builder, msg_target, sig_target, pk_target);

        let msg_vec_target = msg_biguint_target.to_vec_target();
        let r_vec_target = r_biguint_target.to_vec_target();
        let s_vec_target = s_biguint_target.to_vec_target();
        let pk_x_vec_target = pk_x_biguint_target.to_vec_target();
        let pk_y_vec_target = pk_y_biguint_target.to_vec_target();

        let input_vec_target = msg_vec_target
            .into_iter()
            .chain(r_vec_target.into_iter())
            .chain(s_vec_target.into_iter())
            .chain(pk_x_vec_target.into_iter())
            .chain(pk_y_vec_target.into_iter())
            .collect();
        let h = builder
            .hash_n_to_hash_no_pad::<<PoseidonGoldilocksConfig as GenericConfig<D>>::Hasher>(
                input_vec_target,
            );

        let inputs_hash = builder.add_virtual_hash();
        builder.register_public_inputs(&inputs_hash.elements);
        builder.connect_hashes(inputs_hash, h);

        dbg!(builder.num_gates());
        let data: plonky2::plonk::circuit_data::CircuitData<
            plonky2::field::goldilocks_field::GoldilocksField,
            PoseidonGoldilocksConfig,
            2,
        > = builder.build::<C>();

        let mut proofs = Vec::new();
        // let mut hashout_inputs = Vec::new();
        // let hash_common_1 = keccak256(data.common.to_bytes(&gate_serializer).unwrap());
        for _ in 0..3 {
            let mut pw = PartialWitness::new();

            let msg = Secp256K1Scalar::rand();

            let sk = ECDSASecretKey::<Curve>(Secp256K1Scalar::rand());
            let pk = ECDSAPublicKey((CurveScalar(sk.0) * Curve::GENERATOR_PROJECTIVE).to_affine());

            let sig = sign_message(msg, sk);

            let ECDSASignature { r, s } = sig;

            let msg_biguint = msg.to_canonical_biguint();
            let pk_x_biguint = pk.0.x.to_canonical_biguint();
            let pk_y_biguint = pk.0.y.to_canonical_biguint();
            let r_biguint = r.to_canonical_biguint();
            let s_biguint = s.to_canonical_biguint();

            pw.set_biguint_target(&msg_biguint_target, &msg_biguint);
            pw.set_biguint_target(&r_biguint_target, &r_biguint);
            pw.set_biguint_target(&s_biguint_target, &s_biguint);
            pw.set_biguint_target(&pk_x_biguint_target, &pk_x_biguint);
            pw.set_biguint_target(&pk_y_biguint_target, &pk_y_biguint);

            let proof = data.prove(pw).unwrap();
            println!("proof PIS {:?}", proof.public_inputs);
            println!("prove success!!!");

            // let msg_biguint_bytes = msg_biguint.to_bytes_le();
            // let pk_x_biguint_bytes = pk_x_biguint.to_bytes_le();
            // let pk_y_biguint_bytes = pk_y_biguint.to_bytes_le();
            // let r_biguint_bytes = r_biguint.to_bytes_le();
            // let s_biguint_bytes = s_biguint.to_bytes_le();

            // let input_bytes: Vec<u8> = msg_biguint_bytes
            //     .into_iter()
            //     .chain(pk_x_biguint_bytes.into_iter())
            //     .chain(pk_y_biguint_bytes.into_iter())
            //     .chain(r_biguint_bytes.into_iter())
            //     .chain(s_biguint_bytes.into_iter())
            //     .collect();
            // let keccak256_hash_input: [u8; 32] = keccak256(input_bytes);
            // let keccak256_hashout_input = HashOut::<F>::from_bytes(&keccak256_hash_input);
            // keccak256_hashout_inputs.push(keccak256_hashout_input);
            proofs.push(proof);
            // assert!(data.verify(proof).is_ok());
        }

        let ecdsa_inner_cd = data.common;
        let ecdsa_inner_vd = data.verifier_only;

        let mut common_data = common_data_for_recursion::<F, C, D>();
        let config = CircuitConfig::standard_recursion_config();

        // build leaf circuit
        let mut builder = CircuitBuilder::<F, D>::new(config.clone());
        let leaf_targets = builder.tree_recursion_leaf::<C>(ecdsa_inner_cd, &mut common_data)?;
        let data = builder.build::<C>();
        let leaf_vd = &data.verifier_only;

        let mut leaf_proofs = Vec::new();
        // generate leaf proof
        for i in 0..3 {
            let mut pw = PartialWitness::new();
            let leaf_data = TreeRecursionLeafData {
                inner_proof: &proofs[i],
                inner_verifier_data: &ecdsa_inner_vd,
                verifier_data: leaf_vd,
            };
            set_tree_recursion_leaf_data_target(&mut pw, &leaf_targets, &leaf_data)?;
            let leaf_proof = data.prove(pw)?;
            check_tree_proof_verifier_data(&leaf_proof, leaf_vd, &common_data)
                .expect("Leaf 1 public inputs do not match its verifier data");

            leaf_proofs.push(leaf_proof);
        }

        for i in 0..leaf_proofs.len() {
            println!(
                "leaf_proofs {:?} public inputs: {:?}",
                i, leaf_proofs[i].public_inputs
            )
        }

        // build node
        let mut builder = CircuitBuilder::<F, D>::new(config.clone());
        let node_targets = builder.tree_recursion_node::<C>(&mut common_data)?;
        let data = builder.build::<C>();

        let node_vd = &data.verifier_only;

        let mut pw = PartialWitness::new();
        let node_data = TreeRecursionNodeData {
            proof0: &leaf_proofs[0],
            proof1: &leaf_proofs[1],
            verifier_data0: &leaf_vd,
            verifier_data1: &leaf_vd,
            verifier_data: node_vd,
        };
        set_tree_recursion_node_data_target(&mut pw, &node_targets, &node_data)?;
        let node_proof = data.prove(pw)?;
        check_tree_proof_verifier_data(&node_proof, node_vd, &common_data)
            .expect("Node public inputs do not match its verifier data");

        println!("node_proof public inputs: {:?}", node_proof.public_inputs);

        let mut pw = PartialWitness::new();
        let root_data = TreeRecursionNodeData {
            proof0: &node_proof,
            proof1: &leaf_proofs[2],
            verifier_data0: &node_vd,
            verifier_data1: &leaf_vd,
            verifier_data: node_vd,
        };

        set_tree_recursion_node_data_target(&mut pw, &node_targets, &root_data)?;
        let root_proof = data.prove(pw)?;
        check_tree_proof_verifier_data(&root_proof, node_vd, &common_data)
            .expect("Node public inputs do not match its verifier data");

        println!("root_proof public inputs: {:?}", root_proof.public_inputs);

        Ok(())
    }

    type ProofTuple<F, C, const D: usize> = (
        ProofWithPublicInputs<F, C, D>,
        VerifierOnlyCircuitData<C, D>,
        CommonCircuitData<F, D>,
    );

    // fn recursive_proof<
    //     F: RichField + Extendable<D>,
    //     C: GenericConfig<D, F = F>,
    //     InnerC: GenericConfig<D, F = F>,
    //     const D: usize,
    // >(
    //     inner1: &ProofTuple<F, InnerC, D>,
    //     inner2: Option<ProofTuple<F, InnerC, D>>,
    //     config: &CircuitConfig,
    //     min_degree_bits: Option<usize>,
    // ) -> Result<ProofTuple<F, C, D>>
    // where
    //     InnerC::Hasher: AlgebraicHasher<F>,
    //     // [(); C::Hasher::HASH_SIZE]:,
    // {
    //     let mut builder = CircuitBuilder::<F, D>::new(config.clone());
    //     let mut pw = PartialWitness::new();

    //     {
    //         let (inner_proof, inner_vd, inner_cd) = inner1;
    //         let pt = builder.add_virtual_proof_with_pis::<InnerC>(inner_cd);
    //         pw.set_proof_with_pis_target(&pt, inner_proof);
    //         builder.register_public_inputs(&*pt.public_inputs);

    //         let inner_data = VerifierCircuitTarget {
    //             constants_sigmas_cap: builder
    //                 .add_virtual_cap(inner_cd.config.fri_config.cap_height),
    //             circuit_digest: builder.add_virtual_hash(),
    //         };
    //         pw.set_cap_target(
    //             &inner_data.constants_sigmas_cap,
    //             &inner_vd.constants_sigmas_cap,
    //         );
    //         pw.set_hash_target(inner_data.circuit_digest, inner_vd.circuit_digest);

    //         builder.verify_proof::<InnerC>(&pt, &inner_data, inner_cd);
    //     }

    //     if inner2.is_some() {
    //         let (inner_proof, inner_vd, inner_cd) = inner2.unwrap();
    //         let pt = builder.add_virtual_proof_with_pis(&inner_cd);
    //         pw.set_proof_with_pis_target(&pt, &inner_proof);
    //         builder.register_public_inputs(&*pt.public_inputs);

    //         let inner_data = VerifierCircuitTarget {
    //             constants_sigmas_cap: builder
    //                 .add_virtual_cap(inner_cd.config.fri_config.cap_height),
    //             circuit_digest: builder.add_virtual_hash(),
    //         };
    //         pw.set_hash_target(inner_data.circuit_digest, inner_vd.circuit_digest);
    //         pw.set_cap_target(
    //             &inner_data.constants_sigmas_cap,
    //             &inner_vd.constants_sigmas_cap,
    //         );

    //         builder.verify_proof::<InnerC>(&pt, &inner_data, &inner_cd);
    //     }
    //     builder.print_gate_counts(0);

    //     if let Some(min_degree_bits) = min_degree_bits {
    //         // We don't want to pad all the way up to 2^min_degree_bits, as the builder will
    //         // add a few special gates afterward. So just pad to 2^(min_degree_bits
    //         // - 1) + 1. Then the builder will pad to the next power of two,
    //         // 2^min_degree_bits.
    //         let min_gates = (1 << (min_degree_bits - 1)) + 1;
    //         for _ in builder.num_gates()..min_gates {
    //             builder.add_gate(NoopGate, vec![]);
    //         }
    //     }

    //     let data = builder.build::<C>();

    //     let mut timing = TimingTree::new("prove", Level::Info);
    //     let proof = prove(&data.prover_only, &data.common, pw, &mut timing)?;
    //     timing.print();

    //     data.verify(proof.clone())?;

    //     // test_serialization(&proof, &data.verifier_only, &data.common)?;
    //     Ok((proof, data.verifier_only, data.common))
    // }

    fn recursive_proof<
        F: RichField + Extendable<D>,
        C: GenericConfig<D, F = F>,
        InnerC: GenericConfig<D, F = F>,
        const D: usize,
    >(
        inner: &ProofTuple<F, InnerC, D>,
        config: &CircuitConfig,
        min_degree_bits: Option<usize>,
    ) -> Result<ProofTuple<F, C, D>>
    where
        C: GenericConfig<D, F = F>,
        C::Hasher: AlgebraicHasher<F>,
        InnerC::Hasher: AlgebraicHasher<F>,
    {
        let (inner_proof, inner_vd, inner_cd) = inner;
        let mut builder = CircuitBuilder::<F, D>::new(config.clone());
        let pt = builder.add_virtual_proof_with_pis(inner_cd);

        let inner_data = builder.add_virtual_verifier_data(inner_cd.config.fri_config.cap_height);

        builder.verify_proof::<InnerC>(&pt, &inner_data, inner_cd);
        builder.print_gate_counts(0);

        if let Some(min_degree_bits) = min_degree_bits {
            // We don't want to pad all the way up to 2^min_degree_bits, as the builder will
            // add a few special gates afterward. So just pad to 2^(min_degree_bits
            // - 1) + 1. Then the builder will pad to the next power of two,
            // 2^min_degree_bits.
            let min_gates = (1 << (min_degree_bits - 1)) + 1;
            for _ in builder.num_gates()..min_gates {
                builder.add_gate(NoopGate, vec![]);
            }
        }

        // let inputs_hash = builder.add_virtual_hash();
        // let circuit_digest_hash = builder.add_virtual_hash();
        // builder.register_public_inputs(&inputs_hash.elements);
        // builder.register_public_inputs(&circuit_digest_hash.elements);

        // let h = builder.hash_n_to_hash_no_pad::<C::Hasher>(pt.public_inputs.clone());
        // builder.connect_hashes(inputs_hash, h);
        // let h = builder.hash_n_to_hash_no_pad::<C::Hasher>(
        //     [
        //         inner_data.circuit_digest.elements,
        //         verifier_data.circuit_digest.elements,
        //     ]
        //     .concat(),
        // );
        // self.connect_hashes(circuit_digest_hash, h);

        let data = builder.build::<C>();

        let mut pw = PartialWitness::new();
        pw.set_proof_with_pis_target(&pt, inner_proof);
        pw.set_verifier_data_target(&inner_data, inner_vd);

        let mut timing = TimingTree::new("prove", Level::Debug);
        let proof = prove::<F, C, D>(&data.prover_only, &data.common, pw, &mut timing)?;
        timing.print();

        data.verify(proof.clone())?;

        Ok((proof, data.verifier_only, data.common))
    }

    fn test_tree_recursion_with_batch_ecdsa_circuit(config: CircuitConfig) -> Result<()> {
        profiling_enable();
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;

        let batch_num = 1;
        let (
            data,
            v_msg_biguint_target,
            v_r_biguint_target,
            v_s_biguint_target,
            v_pk_x_biguint_target,
            v_pk_y_biguint_target,
        ) = build_batch_ecdsa_circuit(batch_num, config.clone());
        let proof_tuple0 = generate_proof_from_circuit(
            &data,
            &v_msg_biguint_target,
            &v_r_biguint_target,
            &v_s_biguint_target,
            &v_pk_x_biguint_target,
            &v_pk_y_biguint_target,
            batch_num,
        );

        let proof_tuple1 = generate_proof_from_circuit(
            &data,
            &v_msg_biguint_target,
            &v_r_biguint_target,
            &v_s_biguint_target,
            &v_pk_x_biguint_target,
            &v_pk_y_biguint_target,
            batch_num,
        );

        let proof_tuple2 = generate_proof_from_circuit(
            &data,
            &v_msg_biguint_target,
            &v_r_biguint_target,
            &v_s_biguint_target,
            &v_pk_x_biguint_target,
            &v_pk_y_biguint_target,
            batch_num,
        );

        // TODO: remove this double recursion will cause leaf proving error, why?

        // let standard_config = CircuitConfig::standard_recursion_config();
        // let inner1 = recursive_proof::<F, C, C, D>(&proof_tuple0, &standard_config, None)?;
        // let inner2 = recursive_proof::<F, C, C, D>(&proof_tuple1, &standard_config, None)?;
        // let inner3: (
        //     ProofWithPublicInputs<GoldilocksField, PoseidonGoldilocksConfig, 2>,
        //     VerifierOnlyCircuitData<PoseidonGoldilocksConfig, 2>,
        //     CommonCircuitData<GoldilocksField, 2>,
        // ) = recursive_proof::<F, C, C, D>(&proof_tuple2, &standard_config, None)?;

        // let proof_tuples = vec![inner1, inner2, inner3];

        // println!("Num public inputs: {}", inner_cd.num_public_inputs);

        let proof_tuples: Vec<(
            ProofWithPublicInputs<GoldilocksField, PoseidonGoldilocksConfig, 2>,
            VerifierOnlyCircuitData<PoseidonGoldilocksConfig, 2>,
            CommonCircuitData<GoldilocksField, 2>,
        )> = vec![proof_tuple0, proof_tuple1, proof_tuple2];
        let mut common_data = common_data_for_recursion::<F, C, D>();
        let config = CircuitConfig::standard_recursion_config();

        let mut leaf_proofs = Vec::new();

        // build leaf circuit
        let ecdsa_cd = data.common.clone();
        let ecdsa_vd = data.verifier_only.clone();
        let mut builder = CircuitBuilder::<F, D>::new(config.clone());
        let leaf_targets = builder.tree_recursion_leaf::<C>(ecdsa_cd, &mut common_data)?;
        let data = builder.build::<C>();
        let leaf_vd = data.verifier_only.clone();
        let leaf_cd = data.common.clone();

        for i in 0..3 {
            // generate leaf proof
            let mut pw = PartialWitness::new();
            let leaf_data = TreeRecursionLeafData {
                inner_proof: &proof_tuples[i].0,
                inner_verifier_data: &ecdsa_vd,
                verifier_data: &leaf_vd,
            };
            set_tree_recursion_leaf_data_target(&mut pw, &leaf_targets, &leaf_data)?;
            let leaf_proof = data.prove(pw)?;

            // TODO: &common_data OR &leaf_cd ?
            check_tree_proof_verifier_data(&leaf_proof, &leaf_vd, &common_data)
                .expect("Leaf 1 public inputs do not match its verifier data");

            let timing = TimingTree::new("leaf verify", Level::Debug);
            let _ = data.verify(leaf_proof.clone());
            timing.print();

            println!("leaf verify success");
            leaf_proofs.push(leaf_proof);

            // assert_eq!(
            //     common_data, data.common,
            //     "leaf common data is not equal to general common data"
            // );
        }

        for i in 0..leaf_proofs.len() {
            println!(
                "leaf_proofs {:?} public inputs: {:?}",
                i, leaf_proofs[i].public_inputs
            )
        }

        // start to generate secondary leaf node
        let mut secondary_leaf_proofs = Vec::new();

        // build secondary recuisive leaf node
        let mut builder = CircuitBuilder::<F, D>::new(config.clone());
        let leaf_targets = builder.tree_recursion_leaf::<C>(leaf_cd, &mut common_data)?;
        let data = builder.build::<C>();
        let secondary_leaf_vd = &data.verifier_only;

        assert_eq!(
            common_data, data.common,
            "secondary leaf common data is not equal to general common data"
        );

        for i in 0..3 {
            // generate secondary leaf proofs
            let mut pw = PartialWitness::new();
            let leaf_data = TreeRecursionLeafData {
                inner_proof: &leaf_proofs[i],
                inner_verifier_data: &leaf_vd,
                verifier_data: secondary_leaf_vd,
            };
            set_tree_recursion_leaf_data_target(&mut pw, &leaf_targets, &leaf_data)?;
            let leaf_proof = data.prove(pw)?;
            check_tree_proof_verifier_data(&leaf_proof, secondary_leaf_vd, &common_data)
                .expect("Leaf 1 public inputs do not match its verifier data");

            let timing = TimingTree::new("secondary leaf verify", Level::Debug);
            let _ = data.verify(leaf_proof.clone());
            timing.print();
            println!("secondary leaf verify success");
            secondary_leaf_proofs.push(leaf_proof);
        }

        for i in 0..secondary_leaf_proofs.len() {
            println!(
                "secondary_leaf_proofs {:?} public inputs: {:?}",
                i, secondary_leaf_proofs[i].public_inputs
            )
        }

        // build node circuit
        let mut builder = CircuitBuilder::<F, D>::new(config.clone());
        let node_targets = builder.tree_recursion_node::<C>(&mut common_data)?;
        let data = builder.build::<C>();

        let node_vd = &data.verifier_only;

        // generate node proof
        let mut pw = PartialWitness::new();
        let node_data = TreeRecursionNodeData {
            proof0: &secondary_leaf_proofs[0],
            proof1: &secondary_leaf_proofs[1],
            verifier_data0: &secondary_leaf_vd,
            verifier_data1: &secondary_leaf_vd,
            verifier_data: node_vd,
        };
        set_tree_recursion_node_data_target(&mut pw, &node_targets, &node_data)?;
        let node_proof = data.prove(pw)?;
        check_tree_proof_verifier_data(&node_proof, node_vd, &common_data)
            .expect("Node public inputs do not match its verifier data");

        let timing = TimingTree::new("node verify", Level::Debug);
        let _ = data.verify(node_proof.clone());
        timing.print();
        println!("node verify success");

        println!("node_proof public inputs: {:?}", node_proof.public_inputs);

        let mut pw = PartialWitness::new();
        let root_data = TreeRecursionNodeData {
            proof0: &node_proof,
            proof1: &secondary_leaf_proofs[2],
            verifier_data0: &node_vd,
            verifier_data1: &secondary_leaf_vd,
            verifier_data: node_vd,
        };

        set_tree_recursion_node_data_target(&mut pw, &node_targets, &root_data)?;
        let root_proof = data.prove(pw)?;
        check_tree_proof_verifier_data(&root_proof, node_vd, &common_data)
            .expect("Node public inputs do not match its verifier data");

        let timing = TimingTree::new("root verify", Level::Debug);
        let _ = data.verify(root_proof.clone());
        timing.print();
        println!("root_proof verify success");
        println!("root_proof public inputs: {:?}", root_proof.public_inputs);

        Ok(())
    }

    fn build_batch_ecdsa_circuit(
        batch_num: usize,
        config: CircuitConfig,
    ) -> (
        CircuitData<GoldilocksField, PoseidonGoldilocksConfig, 2>,
        Vec<BigUintTarget>,
        Vec<BigUintTarget>,
        Vec<BigUintTarget>,
        Vec<BigUintTarget>,
        Vec<BigUintTarget>,
    ) {
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;
        println!(
            "BATCH SIZE {} GenericConfig {}",
            batch_num,
            C::config_type()
        );

        let mut builder = CircuitBuilder::<F, D>::new(config);

        let mut v_msg_target = Vec::with_capacity(batch_num);
        let mut v_msg_biguint_target = Vec::with_capacity(batch_num);
        let mut v_pk_target = Vec::with_capacity(batch_num);
        let mut v_pk_x_biguint_target = Vec::with_capacity(batch_num);
        let mut v_pk_y_biguint_target = Vec::with_capacity(batch_num);
        let mut v_r_biguint_target = Vec::with_capacity(batch_num);
        let mut v_s_biguint_target = Vec::with_capacity(batch_num);
        let mut v_sig_target = Vec::with_capacity(batch_num);

        for _i in 0..batch_num {
            let msg_target: NonNativeTarget<Secp256K1Scalar> =
                builder.add_virtual_nonnative_target();
            let msg_biguint_target = builder.nonnative_to_canonical_biguint(&msg_target);

            // let pk_target = ECDSAPublicKeyTarget(builder.constant_affine_point(pk.0));
            // TODO: builder.constant_affine_point(pk.0) has an extra debug_assert!(!point.zero);
            let pk_target: ECDSAPublicKeyTarget<Secp256K1> =
                ECDSAPublicKeyTarget(builder.add_virtual_affine_point_target());
            let pk_x_biguint_target = builder.nonnative_to_canonical_biguint(&pk_target.0.x);
            let pk_y_biguint_target = builder.nonnative_to_canonical_biguint(&pk_target.0.y);

            let r_target: NonNativeTarget<Secp256K1Scalar> = builder.add_virtual_nonnative_target();
            let r_biguint_target = builder.nonnative_to_canonical_biguint(&r_target);

            let s_target: NonNativeTarget<_> = builder.add_virtual_nonnative_target();
            let s_biguint_target = builder.nonnative_to_canonical_biguint(&s_target);

            let sig_target: ECDSASignatureTarget<Secp256K1> = ECDSASignatureTarget {
                r: r_target,
                s: s_target,
            };
            v_msg_target.push(msg_target);
            v_msg_biguint_target.push(msg_biguint_target);
            v_pk_target.push(pk_target);
            v_pk_x_biguint_target.push(pk_x_biguint_target);
            v_pk_y_biguint_target.push(pk_y_biguint_target);
            v_r_biguint_target.push(r_biguint_target);
            v_s_biguint_target.push(s_biguint_target);
            v_sig_target.push(sig_target);
        }

        batch_verify_message_circuit(&mut builder, v_msg_target, v_sig_target, v_pk_target);

        assert_eq!(
            v_msg_biguint_target.len(),
            v_pk_x_biguint_target.len(),
            "Length mismatch between v_msg_biguint_target and v_pk_x_biguint_target"
        );
        assert_eq!(
            v_pk_x_biguint_target.len(),
            v_pk_y_biguint_target.len(),
            "Length mismatch between v_pk_x_biguint_target and v_pk_y_biguint_target"
        );
        assert_eq!(
            v_pk_y_biguint_target.len(),
            v_r_biguint_target.len(),
            "Length mismatch between v_pk_y_biguint_target and v_r_biguint_target"
        );
        assert_eq!(
            v_r_biguint_target.len(),
            v_s_biguint_target.len(),
            "Length mismatch between v_r_biguint_target and v_s_biguint_target"
        );

        let mut all_input_vec_targets = Vec::new();

        for i in 0..batch_num {
            let msg_vec_target = v_msg_biguint_target[i].to_vec_target();
            let r_vec_target = v_r_biguint_target[i].to_vec_target();
            let s_vec_target = v_s_biguint_target[i].to_vec_target();
            let pk_x_vec_target = v_pk_x_biguint_target[i].to_vec_target();
            let pk_y_vec_target = v_pk_y_biguint_target[i].to_vec_target();

            let input_vec_target: Vec<Target> = msg_vec_target
                .into_iter()
                .chain(r_vec_target.into_iter())
                .chain(s_vec_target.into_iter())
                .chain(pk_x_vec_target.into_iter())
                .chain(pk_y_vec_target.into_iter())
                .collect();

            all_input_vec_targets.extend(input_vec_target);
        }

        let h = builder
            .hash_n_to_hash_no_pad::<<PoseidonGoldilocksConfig as GenericConfig<D>>::Hasher>(
                all_input_vec_targets,
            );

        let inputs_hash = builder.add_virtual_hash();
        builder.register_public_inputs(&inputs_hash.elements);
        builder.connect_hashes(inputs_hash, h);

        dbg!(builder.num_gates());

        let gate_serializer = CustomGateSerializer;

        let generator_serializer = CustomGeneratorSerializer {
            _phantom: PhantomData::<C>,
            _phantom2: PhantomData::<F>,
        };

        let data: CircuitData<GoldilocksField, PoseidonGoldilocksConfig, 2> = builder.build::<C>();

        // data
        (
            data,
            v_msg_biguint_target,
            v_r_biguint_target,
            v_s_biguint_target,
            v_pk_x_biguint_target,
            v_pk_y_biguint_target,
        )
    }

    fn generate_proof_from_circuit(
        data: &CircuitData<GoldilocksField, PoseidonGoldilocksConfig, 2>,
        v_msg_biguint_target: &Vec<BigUintTarget>,
        v_r_biguint_target: &Vec<BigUintTarget>,
        v_s_biguint_target: &Vec<BigUintTarget>,
        v_pk_x_biguint_target: &Vec<BigUintTarget>,
        v_pk_y_biguint_target: &Vec<BigUintTarget>,
        batch_num: usize,
    ) -> ProofTuple<GoldilocksField, PoseidonGoldilocksConfig, 2> {
        let (msg_list, sig_list, pk_list) = gen_batch_ecdsa_data(batch_num);

        // First Proof
        let mut pw = PartialWitness::new();
        for i in 0..batch_num {
            let ECDSASignature { r, s } = sig_list[i];

            let msg_biguint = msg_list[i].to_canonical_biguint();
            let pk_x_biguint = pk_list[i].0.x.to_canonical_biguint();
            let pk_y_biguint = pk_list[i].0.y.to_canonical_biguint();
            let r_biguint = r.to_canonical_biguint();
            let s_biguint = s.to_canonical_biguint();

            pw.set_biguint_target(&v_msg_biguint_target[i], &msg_biguint);
            pw.set_biguint_target(&v_r_biguint_target[i], &r_biguint);
            pw.set_biguint_target(&v_s_biguint_target[i], &s_biguint);
            pw.set_biguint_target(&v_pk_x_biguint_target[i], &pk_x_biguint);
            pw.set_biguint_target(&v_pk_y_biguint_target[i], &pk_y_biguint);
        }

        let proof = data.prove(pw).unwrap();

        println!("proof PIS {:?}", proof.public_inputs);

        let timing = TimingTree::new("ecdsa verify", Level::Debug);
        data.verify(proof.clone()).unwrap();

        timing.print();
        println!("verify success");
        let proof_tuple = (proof, data.verifier_only.clone(), data.common.clone());

        proof_tuple
    }

    /// Generate a batch of ECDSA data
    fn gen_batch_ecdsa_data(
        batch_num: usize,
    ) -> (
        Vec<Secp256K1Scalar>,
        Vec<ECDSASignature<Secp256K1>>,
        Vec<ECDSAPublicKey<Secp256K1>>,
    ) {
        type Curve = Secp256K1;
        let mut msgs = Vec::with_capacity(batch_num);
        let mut sigs = Vec::with_capacity(batch_num);
        let mut pks = Vec::with_capacity(batch_num);
        for i in 0..batch_num {
            let msg = Secp256K1Scalar::rand();
            let sk = ECDSASecretKey::<Curve>(Secp256K1Scalar::rand());
            let pk = ECDSAPublicKey((CurveScalar(sk.0) * Curve::GENERATOR_PROJECTIVE).to_affine());
            let sig = sign_message(msg, sk);
            let ECDSASignature { r, s } = sig;
            msgs.push(msg);
            pks.push(pk);
            sigs.push(sig);
        }

        (msgs, sigs, pks)
    }

    fn generate_batch_ecdsa_circuit_data_proof_poseidon(
        batch_num: usize,
        config: CircuitConfig,
    ) -> Result<ProofTuple<GoldilocksField, PoseidonGoldilocksConfig, 2>> {
        let (
            data,
            v_msg_biguint_target,
            v_r_biguint_target,
            v_s_biguint_target,
            v_pk_x_biguint_target,
            v_pk_y_biguint_target,
        ) = build_batch_ecdsa_circuit(batch_num, config.clone());
        let proof_tuple = generate_proof_from_circuit(
            &data,
            &v_msg_biguint_target,
            &v_r_biguint_target,
            &v_s_biguint_target,
            &v_pk_x_biguint_target,
            &v_pk_y_biguint_target,
            batch_num,
        );
        Ok(proof_tuple)
    }

    fn test_batch_ecdsa_circuit_with_config(batch_num: usize, config: CircuitConfig) -> Result<()> {
        profiling_enable();
        let _ = generate_batch_ecdsa_circuit_data_proof_poseidon(batch_num, config);
        Ok(())
    }

    fn test_ecdsa_circuit_with_config(config: CircuitConfig) -> Result<()> {
        profiling_enable();
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;

        type Curve = Secp256K1;

        let mut builder = CircuitBuilder::<F, D>::new(config);

        let msg_target = builder.add_virtual_nonnative_target();
        let msg_biguint_target = builder.nonnative_to_canonical_biguint(&msg_target);

        // let pk_target = ECDSAPublicKeyTarget(builder.constant_affine_point(pk.0));
        // TODO: builder.constant_affine_point(pk.0) has an extra debug_assert!(!point.zero);
        let pk_target = ECDSAPublicKeyTarget(builder.add_virtual_affine_point_target());
        let pk_x_biguint_target = builder.nonnative_to_canonical_biguint(&pk_target.0.x);
        let pk_y_biguint_target = builder.nonnative_to_canonical_biguint(&pk_target.0.y);

        let r_target = builder.add_virtual_nonnative_target();
        let r_biguint_target = builder.nonnative_to_canonical_biguint(&r_target);

        let s_target = builder.add_virtual_nonnative_target();
        let s_biguint_target = builder.nonnative_to_canonical_biguint(&s_target);

        let sig_target = ECDSASignatureTarget {
            r: r_target,
            s: s_target,
        };

        verify_message_circuit(&mut builder, msg_target, sig_target, pk_target);

        // let msg_vec_target = msg_biguint_target.to_vec_target();
        // let r_vec_target = r_biguint_target.to_vec_target();
        // let s_vec_target = s_biguint_target.to_vec_target();
        // let pk_x_vec_target = pk_x_biguint_target.to_vec_target();
        // let pk_y_vec_target = pk_y_biguint_target.to_vec_target();

        // let input_vec_target = msg_vec_target
        //     .into_iter()
        //     .chain(r_vec_target.into_iter())
        //     .chain(s_vec_target.into_iter())
        //     .chain(pk_x_vec_target.into_iter())
        //     .chain(pk_y_vec_target.into_iter())
        //     .collect();
        // let h = builder
        //     .hash_n_to_hash_no_pad::<<PoseidonGoldilocksConfig as GenericConfig<D>>::Hasher>(
        //         input_vec_target,
        //     );

        // let inputs_hash = builder.add_virtual_hash();
        // builder.register_public_inputs(&inputs_hash.elements);
        // builder.connect_hashes(inputs_hash, h);

        dbg!(builder.num_gates());
        let data: plonky2::plonk::circuit_data::CircuitData<
            plonky2::field::goldilocks_field::GoldilocksField,
            PoseidonGoldilocksConfig,
            2,
        > = builder.build::<C>();

        for _ in 0..3 {
            let mut pw = PartialWitness::new();

            let msg = Secp256K1Scalar::rand();

            let sk = ECDSASecretKey::<Curve>(Secp256K1Scalar::rand());
            let pk = ECDSAPublicKey((CurveScalar(sk.0) * Curve::GENERATOR_PROJECTIVE).to_affine());

            let sig = sign_message(msg, sk);

            let ECDSASignature { r, s } = sig;

            let msg_biguint = msg.to_canonical_biguint();
            let pk_x_biguint = pk.0.x.to_canonical_biguint();
            let pk_y_biguint = pk.0.y.to_canonical_biguint();
            let r_biguint = r.to_canonical_biguint();
            let s_biguint = s.to_canonical_biguint();

            pw.set_biguint_target(&msg_biguint_target, &msg_biguint);
            pw.set_biguint_target(&r_biguint_target, &r_biguint);
            pw.set_biguint_target(&s_biguint_target, &s_biguint);
            pw.set_biguint_target(&pk_x_biguint_target, &pk_x_biguint);
            pw.set_biguint_target(&pk_y_biguint_target, &pk_y_biguint);

            let proof: plonky2::plonk::proof::ProofWithPublicInputs<
                plonky2::field::goldilocks_field::GoldilocksField,
                PoseidonGoldilocksConfig,
                2,
            > = data.prove(pw).unwrap();
            println!("proof PIS {:?}", proof.public_inputs);
            println!("prove success!!!");
            assert!(data.verify(proof).is_ok());
        }
        Ok(())
    }

    #[test]
    #[ignore]
    fn test_batch_ecdsa_circuit_narrow() -> Result<()> {
        test_batch_ecdsa_circuit_with_config(1, CircuitConfig::standard_ecc_config())
    }

    #[test]
    #[ignore]
    fn test_ecdsa_circuit_narrow() -> Result<()> {
        test_ecdsa_circuit_with_config(CircuitConfig::standard_ecc_config())
    }

    #[test]
    #[ignore]
    fn test_ecdsa_circuit_wide() -> Result<()> {
        test_ecdsa_circuit_with_config(CircuitConfig::wide_ecc_config())
    }

    #[test]
    #[ignore]
    fn test_ecdsa_tree_recursion() -> Result<()> {
        test_tree_recursion_with_ecdsa_circuit(CircuitConfig::standard_ecc_config())
    }

    #[test]
    #[ignore]
    fn test_batch_ecdsa_tree_recursion() -> Result<()> {
        test_tree_recursion_with_batch_ecdsa_circuit(CircuitConfig::standard_ecc_config())
    }
}
