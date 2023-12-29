use std::marker::PhantomData;
use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use plonky2::field::polynomial::PolynomialCoeffs;
use plonky2::field::secp256k1_scalar::Secp256K1Scalar;
use plonky2::field::types::{Field, PrimeField};
use plonky2::fri::proof::FriProof;
use plonky2::hash::merkle_tree::MerkleCap;
use plonky2::iop::witness::PartialWitness;
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::{CircuitConfig, CircuitData, CircuitDataOneDim};
use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};
use plonky2::plonk::proof::{OpeningSet, Proof, ProofWithPublicInputs};
use Plonky2_lib::{ecdsa::gadgets::ecdsa::test_batch_ecdsa_circuit_with_config, profiling_enable};
use Plonky2_lib::ecdsa::curve::ecdsa::ECDSASignature;
use Plonky2_lib::ecdsa::curve::secp256k1::Secp256K1;
use Plonky2_lib::ecdsa::gadgets::biguint::WitnessBigUint;
use Plonky2_lib::ecdsa::gadgets::curve::CircuitBuilderCurve;
use Plonky2_lib::ecdsa::gadgets::ecdsa::{batch_verify_message_circuit, CustomGateSerializer, CustomGeneratorSerializer, ECDSAPublicKeyTarget, ECDSASignatureTarget, gen_batch_ecdsa_data};
use Plonky2_lib::ecdsa::gadgets::nonnative::{CircuitBuilderNonNative, NonNativeTarget};

fn ecdsa_prove_benchmark(c: &mut Criterion) {
    //profiling_enable();
    let mut group = c.benchmark_group("batch_ECDSA_prove_Benchmark_Group");
    group.sample_size(10);
    group.measurement_time(std::time::Duration::from_secs(650));
    group.bench_with_input(BenchmarkId::new("ECDSA_prove_Circuit_Narrow", 1), &1, |b, &_| {
        let batch_num = 20;
        let config = CircuitConfig::standard_ecc_config();
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;
        println!(
            "BATCH SIZE {} GenericConfig {}",
            batch_num,
            C::config_type()
        );

        let mut builder = CircuitBuilder::<F, D>::new(config);

        let (msg_list, sig_list, pk_list) = gen_batch_ecdsa_data(batch_num);

        let mut v_msg_target = Vec::with_capacity(batch_num);
        let mut v_msg_biguint_target = Vec::with_capacity(batch_num);
        let mut v_pk_target = Vec::with_capacity(batch_num);
        let mut v_pk_x_biguint_target = Vec::with_capacity(batch_num);
        let mut v_pk_y_biguint_target = Vec::with_capacity(batch_num);
        let mut v_r_biguint_target = Vec::with_capacity(batch_num);
        let mut v_s_biguint_target = Vec::with_capacity(batch_num);
        let mut v_sig_target = Vec::with_capacity(batch_num);

        for _i in 0..batch_num {
            let msg_target: NonNativeTarget<Secp256K1Scalar> = builder.add_virtual_nonnative_target();
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

        dbg!(builder.num_gates());

        
        let data = builder.build_cuda::<C>();

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

        let mut proof:ProofWithPublicInputs<F, C, D> = ProofWithPublicInputs {
            proof: Proof {
                wires_cap: MerkleCap(vec![]),
                plonk_zs_partial_products_cap: MerkleCap(vec![]),
                quotient_polys_cap: MerkleCap(vec![]),
                openings: OpeningSet {
                    constants: vec![],
                    plonk_sigmas: vec![],
                    wires: vec![],
                    plonk_zs: vec![],
                    plonk_zs_next: vec![],
                    partial_products: vec![],
                    quotient_polys: vec![],
                    lookup_zs: vec![],
                    lookup_zs_next: vec![],
                },
                opening_proof: FriProof {
                    commit_phase_merkle_caps: vec![],
                    query_round_proofs: vec![],
                    final_poly: PolynomialCoeffs { coeffs: vec![] },
                    pow_witness: F::ZERO,
                },
            },
            public_inputs: vec![]
        };

        b.iter(|| {
            let pw = pw.clone();
            proof = data.prove(pw).unwrap();
        });

        println!("proof PIS {:?}", proof.public_inputs);
        data.verify(proof).unwrap();
    });

    group.finish();
}

criterion_group!(benches, ecdsa_prove_benchmark);
criterion_main!(benches);
