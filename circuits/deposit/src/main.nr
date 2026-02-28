use dep::common_merkle::constants::NOTE_COMMITMENT_DOMAIN;
use dep::poseidon::poseidon2::Poseidon2;

fn main(
    // Public inputs: suggested mapping for Solidity deposit verifier inputs.
    commitment: pub Field,
    // Private witness
    secret: Field,
    ownerPubX: Field,
    ownerPubY: Field,
) {
    // Commitment is directly bound to the provided owner public key.
    let computedCommitment: Field =
        Poseidon2::hash([secret, ownerPubX, ownerPubY, NOTE_COMMITMENT_DOMAIN], 4);
    assert(computedCommitment == commitment);
}
