use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    iop::target::{BoolTarget, Target},
    plonk::circuit_builder::CircuitBuilder,
};
use plonky2_u32::gadgets::arithmetic_u32::{CircuitBuilderU32, U32Target};

use super::gates::{
    interleave_u32::U32InterleaveGate, uninterleave_to_b32::UninterleaveToB32Gate,
    uninterleave_to_u32::UninterleaveToU32Gate,
};

pub struct B32Target(pub Target);

/// Efficient binary operations for U32Target
/// Use a combination of arithmetic_u32 and a new interleaved representation
/// The interleaved representation allows for efficient and + xor (using 1 add)
pub trait CircuitBuilderB32<F: RichField + Extendable<D>, const D: usize> {
    // efficient methods that use arithmetic_u32
    fn not_u32(&mut self, x: U32Target) -> U32Target;
    fn lsh_u32(&mut self, x: U32Target, n: u8) -> U32Target;
    fn rsh_u32(&mut self, x: U32Target, n: u8) -> U32Target;
    fn lrot_u32(&mut self, x: U32Target, n: u8) -> U32Target;
    fn rrot_u32(&mut self, x: U32Target, n: u8) -> U32Target;
    fn conditional_u32(&mut self, x: U32Target, y: U32Target, x_or_y: BoolTarget) -> U32Target;

    // see U32InterleaveGate for documentation
    fn interleave_u32(&mut self, x: U32Target) -> B32Target;
    fn uninterleave_to_u32(&mut self, x: Target) -> (U32Target, U32Target);
    fn uninterleave_to_b32(&mut self, x: Target) -> (B32Target, B32Target);

    fn and_xor_u32(&mut self, x: U32Target, y: U32Target) -> (B32Target, B32Target);
    fn and_xor_b32(&mut self, x: B32Target, y: B32Target) -> (B32Target, B32Target);
    fn and_xor_b32_to_u32(&mut self, x: B32Target, y: B32Target) -> (U32Target, U32Target);
    fn and_xor_u32_to_u32(&mut self, x: U32Target, y: U32Target) -> (U32Target, U32Target);

    fn xor_u32(&mut self, x: U32Target, y: U32Target) -> U32Target;
    fn and_u32(&mut self, x: U32Target, y: U32Target) -> U32Target;
    fn unsafe_xor_many_u32(&mut self, x: &[U32Target]) -> U32Target;

    fn not_u64(&mut self, x: &[U32Target; 2]) -> [U32Target; 2];
    fn lrot_u64(&mut self, a: &[U32Target; 2], n: u8) -> [U32Target; 2];
    fn xor_u64(&mut self, x: &[U32Target; 2], y: &[U32Target; 2]) -> [U32Target; 2];
    fn and_u64(&mut self, x: &[U32Target; 2], y: &[U32Target; 2]) -> [U32Target; 2];
    fn unsafe_xor_many_u64(&mut self, x: &[[U32Target; 2]]) -> [U32Target; 2];
    fn conditional_u64(
        &mut self,
        x: &[U32Target; 2],
        y: &[U32Target; 2],
        x_or_y: BoolTarget,
    ) -> [U32Target; 2];
}

impl<F: RichField + Extendable<D>, const D: usize> CircuitBuilderB32<F, D>
    for CircuitBuilder<F, D>
{
    // not := 0xFFFFFFFF - x
    fn not_u32(&mut self, a: U32Target) -> U32Target {
        let zero = self.zero_u32();
        let ff = self.constant_u32(0xFFFFFFFF);
        self.sub_u32(ff, a, zero).0
    }

    // left shift := mul by power of 2, keep lower word
    fn lsh_u32(&mut self, a: U32Target, n: u8) -> U32Target {
        let power_of_two = self.constant_u32(0x1 << n);
        self.mul_u32(a, power_of_two).0
    }

    // right shift := mul by power of 2, keep higher word
    fn rsh_u32(&mut self, a: U32Target, n: u8) -> U32Target {
        if n == 0 {
            return a;
        }
        let power_of_two = self.constant_u32(0x1 << (32 - n));
        self.mul_u32(a, power_of_two).1
    }

    // left rotate := mul by power of 2, adding the two words (they don't overlap)
    fn lrot_u32(&mut self, a: U32Target, n: u8) -> U32Target {
        let power_of_two = self.constant_u32(0x1 << n);
        let (lo, hi) = self.mul_u32(a, power_of_two);
        self.add_u32(lo, hi).0
    }

    // right rotate := left rotate of 32-n
    fn rrot_u32(&mut self, a: U32Target, n: u8) -> U32Target {
        self.lrot_u32(a, 32 - n)
    }

    // convert U32Target -> B32Target by interleaving the bits
    fn interleave_u32(&mut self, x: U32Target) -> B32Target {
        let gate = U32InterleaveGate::new_from_config(&self.config);
        let (row, copy) = self.find_slot(gate, &[], &[]);

        self.connect(Target::wire(row, gate.wire_ith_x(copy)), x.0);

        B32Target(Target::wire(row, gate.wire_ith_x_interleaved(copy)))
    }

    fn uninterleave_to_u32(&mut self, x_dirty: Target) -> (U32Target, U32Target) {
        let gate = UninterleaveToU32Gate::new_from_config(&self.config);
        let (row, copy) = self.find_slot(gate, &[], &[]);

        self.connect(
            Target::wire(row, gate.wire_ith_x_interleaved(copy)),
            x_dirty,
        );

        let x_evens = U32Target(Target::wire(row, gate.wire_ith_x_evens(copy)));
        let x_odds = U32Target(Target::wire(row, gate.wire_ith_x_odds(copy)));

        (x_evens, x_odds)
    }

    fn uninterleave_to_b32(&mut self, x_dirty: Target) -> (B32Target, B32Target) {
        let gate = UninterleaveToB32Gate::new_from_config(&self.config);
        let (row, copy) = self.find_slot(gate, &[], &[]);

        self.connect(
            Target::wire(row, gate.wire_ith_x_interleaved(copy)),
            x_dirty,
        );

        let x_evens = B32Target(Target::wire(row, gate.wire_ith_x_evens(copy)));
        let x_odds = B32Target(Target::wire(row, gate.wire_ith_x_odds(copy)));

        (x_evens, x_odds)
    }

    /// Important! This function is unsafe!
    /// It fails for 3+ inputs all set to 0xffffffff
    ///
    /// More generally, it fails if the sum of the three interleaved inputs for a given iteration exceeds the Goldilocks field characteristic.
    /// In these cases, the sum gets reduced mod the field order and will produce.
    /// If we assume the outputs for a 3-way add of interleaved u32 inputs are uniformly distributed in [0, 2^64-1] (don't think this is actually true but I think close enough),
    /// then the odds of this happening are 1 - ((2^64-2^32+1) / (2^64-1)) = 2.3283064e-10, so it's unlikely to inhibit an honest prover trying to prove something actually correct.
    ///
    /// However, please keep in mind that adversarially this makes it possible in some cases to prove an invalid input hashes to the same result as a valid input.
    /// For example, this circuit can incorrectly prove that 0xffffffff XOR 0xffffffff XOR 0xffffffff is equal to 0x0000fffe.
    /// If you have three inputs whose XOR actually *do* evaluate to 0x0000fffe, then a malicious prover can substitute 0xffffffff for the actual inputs and still produce a valid proof.
    /// Cases like this basically require the first half of the real result to be all 0's, so odds of roughly 1/(2^16) per input triple that this exploit appears
    /// Currently we haven't thought of any particular attacks that can exploit this, but once again should be kept in mind.
    fn unsafe_xor_many_u32(&mut self, x: &[U32Target]) -> U32Target {
        match x.len() {
            0 => self.zero_u32(),
            1 => x[0],
            2 => self.xor_u32(x[0], x[1]),
            3 => {
                let t = self.xor_u32(x[0], x[1]);
                self.xor_u32(t, x[2])
            }
            x_len => {
                // trick: we can do 1x uninterleaved every 2x adds
                // the even bits will be dirty (result of bitwise and),
                // but we only care about the odd bits (result of xor).
                // cost for n elements:
                // - n interleaves
                // - n-1 adds
                // - (n+2)/2 uninterleaves
                let mut r = self.interleave_u32(x[0]);
                for i in 0..(x_len - 3) / 2 {
                    let item_1 = self.interleave_u32(x[1 + i * 2]);
                    let item_2 = self.interleave_u32(x[2 + i * 2]);
                    let t = self.add_many([r.0, item_1.0, item_2.0]);
                    r = self.uninterleave_to_b32(t).1
                }
                if x_len % 2 == 0 {
                    let x_minus_3 = self.interleave_u32(x[x_len - 3]);
                    r = self.and_xor_b32(r, x_minus_3).1
                }
                let x_minus_2 = self.interleave_u32(x[x_len - 2]);
                let x_minus_1 = self.interleave_u32(x[x_len - 1]);
                let t = self.add_many([r.0, x_minus_2.0, x_minus_1.0]);
                self.uninterleave_to_u32(t).1
            }
        }
    }

    fn and_xor_b32(&mut self, x: B32Target, y: B32Target) -> (B32Target, B32Target) {
        let sum = self.add(x.0, y.0);
        self.uninterleave_to_b32(sum)
    }

    fn and_xor_u32(&mut self, x: U32Target, y: U32Target) -> (B32Target, B32Target) {
        let x = self.interleave_u32(x);
        let y = self.interleave_u32(y);
        self.and_xor_b32(x, y)
    }

    fn and_xor_b32_to_u32(&mut self, x: B32Target, y: B32Target) -> (U32Target, U32Target) {
        let sum = self.add(x.0, y.0);
        self.uninterleave_to_u32(sum)
    }

    // x -> X [0 x 0 x 0 x 0 x]
    // y -> Y [0 y 0 y 0 y 0 y]
    // X+Y
    fn and_xor_u32_to_u32(&mut self, x: U32Target, y: U32Target) -> (U32Target, U32Target) {
        let x = self.interleave_u32(x);
        let y = self.interleave_u32(y);
        self.and_xor_b32_to_u32(x, y)
    }

    fn and_u32(&mut self, x: U32Target, y: U32Target) -> U32Target {
        self.and_xor_u32_to_u32(x, y).0
    }

    fn xor_u32(&mut self, x: U32Target, y: U32Target) -> U32Target {
        self.and_xor_u32_to_u32(x, y).1
    }

    fn lrot_u64(&mut self, a: &[U32Target; 2], n: u8) -> [U32Target; 2] {
        let (lo, hi) = if n < 32 { (a[0], a[1]) } else { (a[1], a[0]) };

        let power_of_two = self.constant_u32(0x1 << (n % 32));
        let (lo0, hi0) = self.mul_u32(lo, power_of_two);
        let (lo1, hi1) = self.mul_add_u32(hi, power_of_two, hi0);
        [self.add_u32(lo0, hi1).0, lo1]
    }

    fn unsafe_xor_many_u64(&mut self, x: &[[U32Target; 2]]) -> [U32Target; 2] {
        [
            self.unsafe_xor_many_u32(
                x.iter()
                    .map(|el| el[0])
                    .collect::<Vec<U32Target>>()
                    .as_slice(),
            ),
            self.unsafe_xor_many_u32(
                x.iter()
                    .map(|el| el[1])
                    .collect::<Vec<U32Target>>()
                    .as_slice(),
            ),
        ]
    }

    fn xor_u64(&mut self, x: &[U32Target; 2], y: &[U32Target; 2]) -> [U32Target; 2] {
        [self.xor_u32(x[0], y[0]), self.xor_u32(x[1], y[1])]
    }

    fn and_u64(&mut self, x: &[U32Target; 2], y: &[U32Target; 2]) -> [U32Target; 2] {
        [self.and_u32(x[0], y[0]), self.and_u32(x[1], y[1])]
    }

    fn not_u64(&mut self, x: &[U32Target; 2]) -> [U32Target; 2] {
        [self.not_u32(x[0]), self.not_u32(x[1])]
    }

    // return if z { x } else { y }
    fn conditional_u32(&mut self, x: U32Target, y: U32Target, z: BoolTarget) -> U32Target {
        let not_z = U32Target(self.not(z).target);
        let maybe_x = self.mul_u32(x, U32Target(z.target)).0;
        self.mul_add_u32(y, not_z, maybe_x).0
    }

    fn conditional_u64(
        &mut self,
        x: &[U32Target; 2],
        y: &[U32Target; 2],
        z: BoolTarget,
    ) -> [U32Target; 2] {
        [
            self.conditional_u32(x[0], y[0], z),
            self.conditional_u32(x[1], y[1], z),
        ]
    }
}
