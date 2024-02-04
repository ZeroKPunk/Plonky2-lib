use log::LevelFilter;

extern crate alloc;
extern crate proc_macro;

pub mod hash;
pub mod nonnative;
pub mod u32;
pub mod smt;
pub mod zkdsa;
pub mod poseidon;
pub mod ecdsa;
pub mod zkaa;
pub mod rlp;


pub fn profiling_enable() {
    let mut builder = env_logger::Builder::from_default_env();
    builder.format_timestamp(None);
    builder.filter_level(LevelFilter::Trace);
    builder.try_init().unwrap();
}
