pub mod inclusion;
pub mod common;
pub mod process;

pub use self::{
    inclusion::SparseMerkleInclusionProof,
    process::{verify_smt_process_proof, ProcessMerkleProofRole, SparseMerkleProcessProof},
};
