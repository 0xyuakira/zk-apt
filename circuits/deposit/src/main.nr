use ::common_merkle::constants::NOTE_COMMITMENT_DOMAIN;
use ::poseidon::poseidon2::Poseidon2;
use std::embedded_curve_ops::{EmbeddedCurveScalar, fixed_base_scalar_mul};

fn main(
    // Public inputs
    commitment: pub Field,
    // Private inputs
    secret: Field,
    owner_priv_lo: Field,
    owner_priv_hi: Field,
) {
    // Derive owner pubkey inside the circuit from owner private key limbs.
    let owner_scalar = EmbeddedCurveScalar { lo: owner_priv_lo, hi: owner_priv_hi };
    let derived_owner_pub = fixed_base_scalar_mul(owner_scalar);
    // Commitment is bound to the derived owner public key.
    let computed_commitment: Field = Poseidon2::hash(
        [secret, derived_owner_pub.x, derived_owner_pub.y, NOTE_COMMITMENT_DOMAIN],
        4,
    );
    assert(computed_commitment == commitment);
}
