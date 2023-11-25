use core::marker::PhantomData;

use plonky2::field::extension::Extendable;
use plonky2::field::secp256k1_scalar::Secp256K1Scalar;
use plonky2::hash::hash_types::RichField;
use plonky2::plonk::circuit_builder::CircuitBuilder;

use crate::ecdsa::curve::curve_types::Curve;
use crate::ecdsa::curve::secp256k1::Secp256K1;
use crate::ecdsa::gadgets::curve::{AffinePointTarget, CircuitBuilderCurve};
use crate::ecdsa::gadgets::curve_fixed_base::fixed_base_curve_mul_circuit;
use crate::ecdsa::gadgets::glv::CircuitBuilderGlv;
use crate::ecdsa::gadgets::nonnative::{CircuitBuilderNonNative, NonNativeTarget};

#[derive(Clone, Debug)]
pub struct ECDSASecretKeyTarget<C: Curve>(pub NonNativeTarget<C::ScalarField>);

#[derive(Clone, Debug)]
pub struct ECDSAPublicKeyTarget<C: Curve>(pub AffinePointTarget<C>);

#[derive(Clone, Debug)]
pub struct ECDSASignatureTarget<C: Curve> {
    pub r: NonNativeTarget<C::ScalarField>,
    pub s: NonNativeTarget<C::ScalarField>,
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
    use anyhow::Result;
    use plonky2::field::types::{Sample, PrimeField};
    use plonky2::iop::witness::PartialWitness;
    use plonky2::plonk::circuit_data::CircuitConfig;
    use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};
    use crate::ecdsa::curve::secp256k1;
    use crate::ecdsa::gadgets::biguint::WitnessBigUint;

    use super::*;
    use crate::ecdsa::curve::curve_types::CurveScalar;
    use crate::ecdsa::curve::ecdsa::{sign_message, ECDSAPublicKey, ECDSASecretKey, ECDSASignature};
    use crate::profiling_enable;

    /// Generate a batch of ECDSA data
    fn gen_batch_ecdsa_data<F: RichField + Extendable<D>, const D: usize>(batch_num: usize, builder: &mut CircuitBuilder<F, D>) -> (Vec<NonNativeTarget<Secp256K1Scalar>>, Vec<ECDSASignatureTarget<Secp256K1>>, Vec<ECDSAPublicKeyTarget<Secp256K1>>) {
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;

        type Curve = Secp256K1;
        let mut msgs = Vec::with_capacity(batch_num);
        let mut sigs = Vec::with_capacity(batch_num);
        let mut pks = Vec::with_capacity(batch_num);
        for i in 0..batch_num {
            let msg = Secp256K1Scalar::rand();
            let msg_target = builder.constant_nonnative(msg);
            let sk = ECDSASecretKey::<Curve>(Secp256K1Scalar::rand());
            let pk = ECDSAPublicKey((CurveScalar(sk.0) * Curve::GENERATOR_PROJECTIVE).to_affine());
            let pk_target = ECDSAPublicKeyTarget(builder.constant_affine_point(pk.0));
            let sig = sign_message(msg, sk);

            let ECDSASignature { r, s } = sig;
            let r_target = builder.constant_nonnative(r);
            let s_target = builder.constant_nonnative(s);
            let sig_target = ECDSASignatureTarget {
                r: r_target,
                s: s_target,
            };
            msgs.push(msg_target);
            pks.push(pk_target);
            sigs.push(sig_target);
        };
        (msgs, sigs, pks)
        
    }

    fn test_batch_ecdsa_circuit_with_config(batch_num: usize, config: CircuitConfig) -> Result<()> {
        profiling_enable();
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;

        type Curve = Secp256K1;
        println!("BATCH SIZE {}", batch_num);

        let pw = PartialWitness::new();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        let (msg_target_list, sig_target_list, pk_target_list) = gen_batch_ecdsa_data(batch_num, &mut builder);

        batch_verify_message_circuit(&mut builder, msg_target_list, sig_target_list, pk_target_list);

        dbg!(builder.num_gates());
        let data: plonky2::plonk::circuit_data::CircuitData<plonky2::field::goldilocks_field::GoldilocksField, PoseidonGoldilocksConfig, 2> = builder.build::<C>();
        let proof = data.prove(pw).unwrap();
        println!("proof PIS {:?}", proof.public_inputs);
        data.verify(proof)
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
        let pk_target  = ECDSAPublicKeyTarget(builder.add_virtual_affine_point_target());
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

        dbg!(builder.num_gates());
        let data: plonky2::plonk::circuit_data::CircuitData<plonky2::field::goldilocks_field::GoldilocksField, PoseidonGoldilocksConfig, 2> = builder.build::<C>();
        
        for _ in 0..3{
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
            assert!(data.verify(proof).is_ok());
        }
        Ok(())
    }

    #[test]
    #[ignore]
    fn test_batch_ecdsa_circuit_narrow() -> Result<()> {
        test_batch_ecdsa_circuit_with_config(20, CircuitConfig::standard_ecc_config())
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
}
