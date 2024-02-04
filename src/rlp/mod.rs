use num::BigUint;
use plonky2::{
    field::{extension::Extendable, types::PrimeField64}, hash::hash_types::RichField, iop::{target::{BoolTarget}, witness::Witness}, plonk::circuit_builder::CircuitBuilder
};
use plonky2_u32::{
    gadgets::arithmetic_u32::{CircuitBuilderU32, U32Target},
    witness::WitnessU32,
};

use crate::{nonnative::biguint::{BigUintTarget, CircuitBuilderBiguint}, u32::interleaved_u32::CircuitBuilderB32};


#[derive(Clone, Debug)]
pub struct RlpFieldInputTarget {
    pub field_max_len: usize,
    pub input: BigUintTarget,
    pub len_len: usize,
}

#[derive(Clone, Debug)]
pub struct RlpFieldPrefixParsed {
    is_not_literal: U32Target,
    is_big: U32Target,
    next_len: U32Target,
    len_len: U32Target,
}

/// Returns the number of bits needed to represent the value of `x`.
pub fn bit_length(x: u64) -> usize {
    (u64::BITS - x.leading_zeros()) as usize
}

pub fn max_rlp_len_len(max_len: usize) -> usize {
    if max_len > 55 {
        (bit_length(max_len as u64) + 7) / 8
    } else {
        0
    }
}

pub fn parse_rlp_field_len_len(value: &[u8]) -> usize {
    let mut len_len = 0;
    let mut len = value.len() - 1;
    if len > 55 {
        let len_cells_len = (value[0] - 183) as usize;
        let len_ceslls = &value[1..1 + len_cells_len];
        for i in 0..len_cells_len {
            len_len = len_len << 8 | len_ceslls[i] as usize;
        }
    }
    len_len
}

pub trait WitnessRLP<F: PrimeField64>: Witness<F> {
    fn set_rlp_field_target_witness(&mut self, target: &RlpFieldInputTarget, value: &[u8]);
    fn set_rlp_array_target_witness();
}

impl<T: Witness<F>, F: PrimeField64> WitnessRLP<F> for T {
    fn set_rlp_field_target_witness(&mut self, target: &RlpFieldInputTarget, value: &[u8]) {
        let input_biguint = BigUint::from_bytes_be(value);
        let mut limbs = input_biguint.to_bytes_le();
        limbs.reverse();
        // assert!(target.input.num_limbs() >= limbs.len());
        limbs.resize(target.input.num_limbs(), 0);
        for i in 0..target.input.num_limbs() {
            // println!("set_rlp_field_target_witness: limbs[{}] = {}", i, limbs[i]);
            self.set_u32_target(target.input.limbs[i], limbs[i] as u32);
        }
        // target.update_len_len(value);
    }

    fn set_rlp_array_target_witness() {}
}

pub trait CircuitBuilderRLP<F: RichField + Extendable<D>, const D: usize> {
    fn add_virtual_rlp_field_target(&mut self, max_field_len: usize) -> RlpFieldInputTarget;
    fn rlp_field(&mut self, encoded_target: &RlpFieldInputTarget);
    fn witness_subarray(&mut self, array: &[U32Target], start_id: usize, start_id_target: &U32Target, sub_len: usize, sub_len_target: &U32Target, max_len: usize) -> Vec<U32Target>;
    fn evaluate_byte_array(&mut self, array: &[U32Target], len: &U32Target) -> U32Target;
    fn parse_rlp_len(&mut self, rlp_cells: &[U32Target], len_len: usize, len_len_target: U32Target, max_len: usize) -> (Vec<U32Target>, U32Target);
    fn parse_rlp_field_prefix(&mut self, prefix: &U32Target) -> RlpFieldPrefixParsed;
    // fn parse_rlp_field_prefix(&mut self, prefix: &U32Target);

    fn rlp_array(&mut self);
}

impl<F: RichField + Extendable<D>, const D: usize> CircuitBuilderRLP<F, D>
    for CircuitBuilder<F, D>
{
    fn add_virtual_rlp_field_target(&mut self, max_field_len: usize) -> RlpFieldInputTarget {
        let input = self.add_virtual_biguint_target(max_field_len + 1);
        return RlpFieldInputTarget {
            len_len: 0,
            field_max_len: max_field_len,
            input,
        };
    }


    fn rlp_field(&mut self, rlp_field: &RlpFieldInputTarget) {
        let field_max_len = rlp_field.field_max_len;
        let max_len_len = max_rlp_len_len(field_max_len);
        // debug_assert_eq!(rlp_field.input.num_limbs(), 1 + max_len_len + field_max_len);

        let prefix_parsed = self.parse_rlp_field_prefix(&rlp_field.input.limbs[0]);
        let (low_prefix, _) = self.mul_u32(rlp_field.input.limbs[0], prefix_parsed.is_not_literal);
        let len_len = prefix_parsed.len_len;

        // // for debug parsed.len_len = 2
        // let const_len_len = self.constant_u32(2);
        // self.connect_u32(const_len_len, prefix_parsed.len_len);

        // self.check_less_than_safe_u32(len_len, (max_len_len + 1) as u32);

        // let (len_cells, len_val) = self.parse_rlp_len(&rlp_field.input.limbs, rlp_field.len_len, len_len, max_len_len);
    }

    fn witness_subarray(&mut self, array: &[U32Target], start_id: usize, start_id_target: &U32Target, sub_len: usize, sub_len_target: &U32Target, max_len: usize) -> Vec<U32Target> {
        // transfer U32Target to usize
        let constant_start_id = self.constant_u32(start_id as u32);
        self.connect_u32(*start_id_target, constant_start_id);
        let constant_sub_len = self.constant_u32(sub_len as u32);
        self.connect_u32(*sub_len_target, constant_sub_len);
        debug_assert!(sub_len <= max_len, "{sub_len} > {max_len}");

        self.copy_many_u32( &array[start_id..start_id + sub_len])
    }

    fn evaluate_byte_array(&mut self, array: &[U32Target], len: &U32Target) -> U32Target {
        let constant_256 = self.constant_u32(256);
        let mut byte_accumulator = self.one_u32();
        let const_one = self.one_u32();
        let mut len_counter = self.zero_u32();
        let mut byte_val = self.zero_u32();
        // reverse the array
        println!("array.len() = {}", array.len());
        for i in (0..array.len()).rev() {
            let (tmp, _) = self.mul_u32(array[i], byte_accumulator);
            (byte_val, _) = self.add_u32(byte_val, tmp);
            (byte_accumulator, _) = self.mul_u32(byte_accumulator, constant_256);
            (len_counter, _) = self.add_u32(len_counter, const_one);
        }

        let const_1024 = self.constant_u32(1023);
        // self.connect_u32(const_1024, *len);
        self.connect_u32(const_1024, len_counter);

        self.connect_u32(len_counter, *len);
        byte_val
    }

    fn parse_rlp_len(&mut self, rlp_cells: &[U32Target], len_len: usize, len_len_target: U32Target, max_len: usize) -> (Vec<U32Target>, U32Target) {
        let zero = self.zero_u32();
        let len_cells = self.witness_subarray(rlp_cells, 0,&zero, len_len ,&len_len_target, max_len);

        let len_val = self.evaluate_byte_array(&len_cells, &len_len_target);
        (len_cells, len_val)
    }

    fn parse_rlp_field_prefix(&mut self, prefix: &U32Target) -> RlpFieldPrefixParsed{
        let const_127 = self.constant_u32(127);
        let const_184 = self.constant_u32(184);
        let const_192 = self.constant_u32(192);
        let const_128 = self.constant_u32(128);
        let const_183 = self.constant_u32(183);
        let const_one = self.one_u32();
        let const_one_target = self.constant(F::from_canonical_u32(1));
        let const_zero = self.zero_u32();
        let borrow = self.zero_u32();
        let num_bits = 32;
        // if prefix < 128 => prefix in [0, 127], the string is a single byte, the field length is 1, whhich is its own RLP encoding
        let is_not_literal = 
            self.is_less_than_u32(const_127, *prefix, num_bits);

        // if prefix < 184 => prefix in [128, 183], the string shouble be in 0-55 bytes long, the field length is prefix - 128
        let is_len_or_literal = 
            self.is_less_than_u32(*prefix, const_184, num_bits);

        //  // for debug is_len_or_literal = false
        //  let const_is_false = self.constant_u32(0);
        //  self.connect_u32(const_is_false, U32Target(is_len_or_literal.target));

        // prefix >=184, the following _(prefix - 183)_ bytes denote the length of the actual string, the length is in binary form
        // Bit logic of (not is_len_or_literal)
        let is_big = BoolTarget::new_unsafe(self.sub(const_one_target, is_len_or_literal.target));

        // // for debug is_big = true
        // let const_is_true = self.constant_u32(1);
        // self.connect_u32(const_is_true, U32Target(is_big.target));
        
        // is valid
        self.check_less_than_u32(*prefix, const_192, num_bits);

        let (field_len, _) = self.sub_u32(*prefix, const_128, borrow);

        let (len_len, _) = self.sub_u32(*prefix, const_183, borrow);

        // // for debug len_len = 2
        // let const_2 = self.constant_u32(2);
        // self.connect_u32(const_2, len_len);

        // // for debug is_big = true
        // let const_is_true = self.constant_u32(1);
        // self.connect_u32(const_is_true, U32Target(is_big.target));

        let next_len = self.select_u32(is_big, len_len, field_len);

        // // for debug next_len = 2
        // let const_2 = self.constant_u32(2);
        // self.connect_u32(const_2, next_len);

        let next_len = self.select_u32(is_not_literal, next_len, const_one);

        // // for debug next_len = 2
        // let const_2 = self.constant_u32(4);
        // self.connect_u32(const_2, next_len);

        let (low_len_len, _) = self.mul_u32(len_len, U32Target(is_big.target));
        let (len_len, _) = self.mul_u32(U32Target(is_not_literal.target), low_len_len);
        RlpFieldPrefixParsed { 
            is_not_literal: U32Target(is_not_literal.target), 
            is_big: U32Target(is_big.target), 
            next_len, 
            len_len
        }

    }
    fn rlp_array(&mut self) {}
}

#[cfg(test)]
mod tests {
    use ethers_core::utils::hex::FromHex;
    use plonky2::{iop::witness::PartialWitness, plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::CircuitConfig,
        config::{GenericConfig, PoseidonGoldilocksConfig},
    }};
    use crate::rlp::{ CircuitBuilderRLP, WitnessRLP };

    #[test]
    fn test_short_rlp_field_circuit() {
        // build circuit once
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;
        println!("DDDDDD");
            
        let test_cases = [
            // Vec::from_hex("77").unwrap(), // single byte
            // Vec::from_hex("8100").unwrap(), // single byte
            // Vec::from_hex("820000").unwrap(), // 2 bytes
            // Vec::from_hex("8300011000").unwrap(), // 3 bytes
            Vec::from_hex("b904004c6f72656d20697073756d20646f6c6f722073697420616d65742c20636f6e73656374657475722061646970697363696e6720656c69742e20437572616269747572206d6175726973206d61676e612c20737573636970697420736564207665686963756c61206e6f6e2c20696163756c697320666175636962757320746f72746f722e2050726f696e20737573636970697420756c74726963696573206d616c6573756164612e204475697320746f72746f7220656c69742c2064696374756d2071756973207472697374697175652065752c20756c7472696365732061742072697375732e204d6f72626920612065737420696d70657264696574206d6920756c6c616d636f7270657220616c6971756574207375736369706974206e6563206c6f72656d2e2041656e65616e2071756973206c656f206d6f6c6c69732c2076756c70757461746520656c6974207661726975732c20636f6e73657175617420656e696d2e204e756c6c6120756c74726963657320747572706973206a7573746f2c20657420706f73756572652075726e6120636f6e7365637465747572206e65632e2050726f696e206e6f6e20636f6e76616c6c6973206d657475732e20446f6e65632074656d706f7220697073756d20696e206d617572697320636f6e67756520736f6c6c696369747564696e2e20566573746962756c756d20616e746520697073756d207072696d697320696e206661756369627573206f726369206c756374757320657420756c74726963657320706f737565726520637562696c69612043757261653b2053757370656e646973736520636f6e76616c6c69732073656d2076656c206d617373612066617563696275732c2065676574206c6163696e6961206c616375732074656d706f722e204e756c6c61207175697320756c747269636965732070757275732e2050726f696e20617563746f722072686f6e637573206e69626820636f6e64696d656e74756d206d6f6c6c69732e20416c697175616d20636f6e73657175617420656e696d206174206d65747573206c75637475732c206120656c656966656e6420707572757320656765737461732e20437572616269747572206174206e696268206d657475732e204e616d20626962656e64756d2c206e6571756520617420617563746f72207472697374697175652c206c6f72656d206c696265726f20616c697175657420617263752c206e6f6e20696e74657264756d2074656c6c7573206c65637475732073697420616d65742065726f732e20437261732072686f6e6375732c206d65747573206163206f726e617265206375727375732c20646f6c6f72206a7573746f20756c747269636573206d657475732c20617420756c6c616d636f7270657220766f6c7574706174").unwrap(), // 1024 bytes
        ];
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        let rlp_field_input_target = builder.add_virtual_rlp_field_target(1024);
        builder.rlp_field(&rlp_field_input_target);
        let data = builder.build::<C>();
        for input_bytes in test_cases.iter() {
            let mut pw = PartialWitness::new();
            pw.set_rlp_field_target_witness(&rlp_field_input_target, &input_bytes);
            let proof = data.prove(pw).unwrap();
            assert!(data.verify(proof).is_ok());
            // println!("test {:?} success", input_bytes);
        }
       
    }
}
