use ::common_merkle::constants::NOTE_COMMITMENT_DOMAIN;
use ::common_merkle::constants::NULLIFIER_DOMAIN;
use ::common_merkle::merkle;
use ::poseidon::poseidon2::Poseidon2;
use std::embedded_curve_ops::{
    EmbeddedCurvePoint, EmbeddedCurveScalar, fixed_base_scalar_mul, multi_scalar_mul,
};

fn main(
    // Public inputs
    audit_pub_x: pub Field,
    audit_pub_y: pub Field,
    merkle_root: pub Field,
    transfer_commitment: pub Field,
    nullifier_hash: pub Field,
    encrypted_recipient_payload: pub Field,
    encrypted_audit_payload: pub Field,
    ephemeral_pub_x: pub Field,
    ephemeral_pub_y: pub Field,
    cipher_nonce: pub Field,
    // Private inputs
    secret: Field,
    owner_priv_lo: u128,
    owner_priv_hi: u128,
    new_secret: Field,
    recipient_pub_x: Field,
    recipient_pub_y: Field,
    ephemeral_priv_lo: u128,
    ephemeral_priv_hi: u128,
    merkle_path: [Field; 20],
    merkle_index_bits: [bool; 20],
) {
    // Derive spender public key from the provided private key limbs.
    let owner_scalar: EmbeddedCurveScalar =
        EmbeddedCurveScalar { lo: owner_priv_lo as Field, hi: owner_priv_hi as Field };
    let derived_owner_pub = fixed_base_scalar_mul(owner_scalar);

    // Old note membership: note is bound to derived owner pubkey.
    let commitment = Poseidon2::hash(
        [secret, derived_owner_pub.x, derived_owner_pub.y, NOTE_COMMITMENT_DOMAIN],
        4,
    );
    merkle::assert_membership(merkle_root, commitment, merkle_path, merkle_index_bits);

    // Nullifier must be bound to both secret and spender private key limbs.
    let computed_nullifier_hash = Poseidon2::hash(
        [secret, owner_priv_lo as Field, owner_priv_hi as Field, NULLIFIER_DOMAIN],
        4,
    );
    assert(computed_nullifier_hash == nullifier_hash);

    // New output note commitment must be derived from fresh secret material.
    let computed_transfer_commitment = Poseidon2::hash(
        [new_secret, recipient_pub_x, recipient_pub_y, NOTE_COMMITMENT_DOMAIN],
        4,
    );
    assert(computed_transfer_commitment == transfer_commitment);

    // Ephemeral pubkeys must match witness private scalars.
    let ephemeral_scalar =
        EmbeddedCurveScalar { lo: ephemeral_priv_lo as Field, hi: ephemeral_priv_hi as Field };
    let ephemeral_pub = fixed_base_scalar_mul(ephemeral_scalar);
    assert(ephemeral_pub.x == ephemeral_pub_x);
    assert(ephemeral_pub.y == ephemeral_pub_y);

    // Encrypted payload consistency using ECDH shared point
    // 1.Receiver channel ECDH and symmetric key.
    let recipient_pub_point =
        EmbeddedCurvePoint { x: recipient_pub_x, y: recipient_pub_y, is_infinite: false };
    let shared_recipient_point = multi_scalar_mul([recipient_pub_point], [ephemeral_scalar]);
    let k_recipient = Poseidon2::hash([shared_recipient_point.x, shared_recipient_point.y], 2);

    // 2.Audit channel ECDH and symmetric key.
    let audit_pub_point = EmbeddedCurvePoint { x: audit_pub_x, y: audit_pub_y, is_infinite: false };
    let shared_audit_point = multi_scalar_mul([audit_pub_point], [ephemeral_scalar]);
    let k_audit = Poseidon2::hash([shared_audit_point.x, shared_audit_point.y], 2);

    // 3.Per-channel masks derived from key + nonce.
    let recipient_mask = Poseidon2::hash([k_recipient, cipher_nonce], 2);
    let audit_mask = Poseidon2::hash([k_audit, cipher_nonce], 2);

    // 4.recipient gets new_secret; audit gets raw old commitment for tracing.
    let computed_encrypted_recipient_payload = new_secret + recipient_mask;
    let computed_encrypted_audit_payload = commitment + audit_mask;
    assert(computed_encrypted_recipient_payload == encrypted_recipient_payload);
    assert(computed_encrypted_audit_payload == encrypted_audit_payload);
}
