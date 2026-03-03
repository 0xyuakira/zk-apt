use ::common_merkle::constants::NOTE_COMMITMENT_DOMAIN;
use ::common_merkle::constants::NULLIFIER_DOMAIN;
use ::common_merkle::constants::WITHDRAW_AUDIT_PAYLOAD_DOMAIN;
use ::common_merkle::merkle;
use ::poseidon::poseidon2::Poseidon2;
use std::embedded_curve_ops::{EmbeddedCurvePoint, EmbeddedCurveScalar, multi_scalar_mul};

fn main(
    // Public inputs: must align with Solidity withdraw publicInputs[0..8]
    merkle_root: pub Field,
    audit_pub_x: pub Field,
    audit_pub_y: pub Field,
    nullifier_hash: pub Field,
    encrypted_audit_payload: pub Field,
    audit_ephemeral_pub_x: pub Field,
    audit_ephemeral_pub_y: pub Field,
    cipher_nonce: pub Field,
    recipient: pub Field,
    // Private witness
    secret: Field,
    owner_pub_x: Field,
    owner_pub_y: Field,
    owner_priv_lo: u128,
    owner_priv_hi: u128,
    audit_ephemeral_priv_lo: u128,
    audit_ephemeral_priv_hi: u128,
    merkle_path: [Field; 20],
    merkle_index_bits: [bool; 20],
) {
    // Old note membership: note is bound to provided owner pubkey.
    let commitment = Poseidon2::hash(
        [secret, owner_pub_x, owner_pub_y, NOTE_COMMITMENT_DOMAIN],
        4,
    );
    merkle::assert_membership(merkle_root, commitment, merkle_path, merkle_index_bits);

    // Nullifier must be bound to both secret and spender private key limbs.
    let computed_nullifier_hash = Poseidon2::hash(
        [secret, owner_priv_lo as Field, owner_priv_hi as Field, NULLIFIER_DOMAIN],
        4,
    );
    assert(computed_nullifier_hash == nullifier_hash);

    // Ephemeral pubkey must match witness private scalar.
    let ecdh_generator: [EmbeddedCurvePoint; 1] =
        std::hash::derive_generators("APT_ECDH".as_bytes(), 0);
    // Full-scalar witness: two constrained 128-bit limbs.
    let audit_ephemeral_scalar = EmbeddedCurveScalar {
        lo: audit_ephemeral_priv_lo as Field,
        hi: audit_ephemeral_priv_hi as Field,
    };
    let derived_audit_ephemeral_pub = multi_scalar_mul(ecdh_generator, [audit_ephemeral_scalar]);
    assert(derived_audit_ephemeral_pub.x == audit_ephemeral_pub_x);
    assert(derived_audit_ephemeral_pub.y == audit_ephemeral_pub_y);

    // Bind withdraw encrypted audit payload using real ECDH shared point.
    let audit_pub_point = EmbeddedCurvePoint { x: audit_pub_x, y: audit_pub_y, is_infinite: false };
    let shared_audit_point = multi_scalar_mul([audit_pub_point], [audit_ephemeral_scalar]);
    let k_audit = Poseidon2::hash([shared_audit_point.x, shared_audit_point.y], 2);
    let audit_payload = Poseidon2::hash(
        [commitment, nullifier_hash, recipient, WITHDRAW_AUDIT_PAYLOAD_DOMAIN],
        4,
    );
    let audit_mask = Poseidon2::hash([k_audit, cipher_nonce], 2);
    let computed_encrypted_audit_payload = audit_payload + audit_mask;
    assert(computed_encrypted_audit_payload == encrypted_audit_payload);
}
