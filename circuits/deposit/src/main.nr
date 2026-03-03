use ::common_merkle::constants::NOTE_COMMITMENT_DOMAIN;
use ::poseidon::poseidon2::Poseidon2;
use std::embedded_curve_ops::{EmbeddedCurveScalar, fixed_base_scalar_mul};

fn main(
    // Public inputs: suggested mapping for Solidity deposit verifier inputs.
    commitment: pub Field,
    // Private witness
    secret: Field,
    ownerPrivLo: Field,
    ownerPrivHi: Field,
    ownerPubX: Field,
    ownerPubY: Field,
) {
    // Bind provided owner pubkey to provided private key to prevent note lock due to wrong pub input.
    let ownerScalar = EmbeddedCurveScalar { lo: ownerPrivLo, hi: ownerPrivHi };
    let derivedOwnerPub = fixed_base_scalar_mul(ownerScalar);
    assert(derivedOwnerPub.x == ownerPubX);
    assert(derivedOwnerPub.y == ownerPubY);

    // Commitment is directly bound to the provided owner public key.
    let computedCommitment: Field =
        Poseidon2::hash([secret, ownerPubX, ownerPubY, NOTE_COMMITMENT_DOMAIN], 4);
    assert(computedCommitment == commitment);
}
