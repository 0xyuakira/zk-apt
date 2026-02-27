use dep::common_merkle::constants::NOTE_COMMITMENT_DOMAIN;
use dep::poseidon::poseidon2::Poseidon2;
use std::embedded_curve_ops::{EmbeddedCurvePoint, EmbeddedCurveScalar, multi_scalar_mul};

fn main(
    // Public inputs: suggested mapping for Solidity deposit verifier inputs.
    commitment: pub Field,
    // Private witness
    secret: Field,
    ownerPrivLo: u128,
    ownerPrivHi: u128,
) {
    // Deposit note is owned by the depositor's spending key.
    let ownerScalar = EmbeddedCurveScalar { lo: ownerPrivLo as Field, hi: ownerPrivHi as Field };
    let ownerGenerator: [EmbeddedCurvePoint; 1] =
        std::hash::derive_generators("APT_OWNER".as_bytes(), 0);
    let ownerPub = multi_scalar_mul(ownerGenerator, [ownerScalar]);

    let computedCommitment = Poseidon2::hash(
        [secret, ownerPub.x, ownerPub.y, NOTE_COMMITMENT_DOMAIN],
        4,
    );
    assert(computedCommitment == commitment);
}

