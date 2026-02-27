use dep::common_merkle::merkle;
use dep::common_merkle::constants::NOTE_COMMITMENT_DOMAIN;
use dep::common_merkle::constants::NULLIFIER_DOMAIN;
use dep::poseidon::poseidon2::Poseidon2;
use std::embedded_curve_ops::{EmbeddedCurvePoint, EmbeddedCurveScalar, multi_scalar_mul};

fn enc_note_data(note_data: Field, shared_key: Field) -> Field {
    note_data + shared_key
}

fn main(
    // Public inputs: must align with Solidity submitTransfer publicInputs[0..11]
    auditPubX: pub Field,
    auditPubY: pub Field,
    merkleRoot: pub Field,
    transferCommitment: pub Field,
    nullifierHash: pub Field,
    encryptedNoteDataReceiver: pub Field,
    encryptedNoteDataAudit: pub Field,
    receiverEphemeralPubX: pub Field,
    receiverEphemeralPubY: pub Field,
    auditEphemeralPubX: pub Field,
    auditEphemeralPubY: pub Field,
    cipherNonce: pub Field,
    // Private witness
    secret: Field,
    ownerPrivLo: u128,
    ownerPrivHi: u128,
    newSecret: Field,
    receiverPubX: Field,
    receiverPubY: Field,
    receiverEphemeralPrivLo: u128,
    receiverEphemeralPrivHi: u128,
    auditEphemeralPrivLo: u128,
    auditEphemeralPrivHi: u128,
    merklePath: [Field; 20],
    merkleIndexBits: [bool; 20],
) {
    // Owner key material for spending authority of the old note.
    let ownerScalar = EmbeddedCurveScalar { lo: ownerPrivLo as Field, hi: ownerPrivHi as Field };
    let ownerGenerator: [EmbeddedCurvePoint; 1] =
        std::hash::derive_generators("APT_OWNER".as_bytes(), 0);
    let ownerPub = multi_scalar_mul(ownerGenerator, [ownerScalar]);

    // Old note membership: note is bound to owner pubkey.
    let commitment = Poseidon2::hash([secret, ownerPub.x, ownerPub.y, NOTE_COMMITMENT_DOMAIN], 4);
    merkle::assert_membership(merkleRoot, commitment, merklePath, merkleIndexBits);

    // Nullifier must be bound to both secret and spender private key limbs.
    let computedNullifierHash = Poseidon2::hash(
        [secret, ownerPrivLo as Field, ownerPrivHi as Field, NULLIFIER_DOMAIN],
        4,
    );
    assert(computedNullifierHash == nullifierHash);

    // New output note commitment must be derived from fresh secret material.
    let computedTransferCommitment = Poseidon2::hash(
        [newSecret, receiverPubX, receiverPubY, NOTE_COMMITMENT_DOMAIN],
        4,
    );
    assert(computedTransferCommitment == transferCommitment);

    // Ephemeral pubkeys must match witness private scalars
    let ecdh_generator: [EmbeddedCurvePoint; 1] =
        std::hash::derive_generators("APT_ECDH".as_bytes(), 0);
    let receiverEphemeralScalar = EmbeddedCurveScalar {
        lo: receiverEphemeralPrivLo as Field,
        hi: receiverEphemeralPrivHi as Field,
    };
    // Full-scalar witness: two constrained 128-bit limbs.
    let auditEphemeralScalar = EmbeddedCurveScalar {
        lo: auditEphemeralPrivLo as Field,
        hi: auditEphemeralPrivHi as Field,
    };
    let receiverEphemeralPub = multi_scalar_mul(ecdh_generator, [receiverEphemeralScalar]);
    let auditEphemeralPub = multi_scalar_mul(ecdh_generator, [auditEphemeralScalar]);
    assert(receiverEphemeralPub.x == receiverEphemeralPubX);
    assert(receiverEphemeralPub.y == receiverEphemeralPubY);
    assert(auditEphemeralPub.x == auditEphemeralPubX);
    assert(auditEphemeralPub.y == auditEphemeralPubY);

    // Encrypted payload consistency
    let receiverPubPoint =
        EmbeddedCurvePoint { x: receiverPubX, y: receiverPubY, is_infinite: false };
    let sharedReceiverPoint = multi_scalar_mul([receiverPubPoint], [receiverEphemeralScalar]);
    let kReceiver = Poseidon2::hash([sharedReceiverPoint.x, sharedReceiverPoint.y], 2);
    let auditPubPoint = EmbeddedCurvePoint { x: auditPubX, y: auditPubY, is_infinite: false };
    let sharedAuditPoint = multi_scalar_mul([auditPubPoint], [auditEphemeralScalar]);
    let kAudit = Poseidon2::hash([sharedAuditPoint.x, sharedAuditPoint.y], 2);
    // Receiver gets fresh secret for the new note, audit gets lineage payload.
    let auditPayload = Poseidon2::hash([commitment, transferCommitment], 2);
    let receiverMask = Poseidon2::hash([kReceiver, cipherNonce], 2);
    let auditMask = Poseidon2::hash([kAudit, cipherNonce], 2);
    let computedEncryptedNoteDataReceiver = enc_note_data(newSecret, receiverMask);
    let computedEncryptedNoteDataAudit = enc_note_data(auditPayload, auditMask);
    assert(computedEncryptedNoteDataReceiver == encryptedNoteDataReceiver);
    assert(computedEncryptedNoteDataAudit == encryptedNoteDataAudit);
}
