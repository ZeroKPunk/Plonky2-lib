
use Plonky2_lib::ecdsa::gadgets::ecdsa::test_batch_ecdsa_circuit_with_config;
use plonky2::plonk::circuit_data::CircuitConfig;



fn main() {
    test_batch_ecdsa_circuit_with_config(20, CircuitConfig::standard_ecc_config());
}