// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {AptTestBase} from "./AptTestBase.t.sol";
import {AuditablePrivacyTransfer} from "../src/AuditablePrivacyTransfer.sol";

contract TransferTest is AptTestBase {
    function testTransferWithRealProofViaFFI() public {
        (uint256 ownerPrivLo, uint256 ownerPrivHi, uint256 ownerPubX, uint256 ownerPubY) =
            _getKeyPair(uint256(keccak256("transfer-user")));
        (uint256 recipientPrivLo, uint256 recipientPrivHi, uint256 recipientPubX, uint256 recipientPubY) =
            _getKeyPair(uint256(keccak256("recipient-user")));

        uint256 secret = uint256(keccak256(abi.encodePacked("transfer-secret", block.timestamp))) % BN254_R;
        uint256 commitment = _getCommitment(secret, ownerPubX, ownerPubY);

        (bytes memory depositProof,) = _generateDepositProof(commitment, secret, ownerPrivLo, ownerPrivHi);
        apt.deposit{value: 1 ether}(depositProof, commitment);

        uint256 newSecret = uint256(keccak256(abi.encodePacked("transfer-new-secret", block.timestamp))) % BN254_R;
        (bytes memory transferProof, bytes32[] memory pub) = _generateTransferProof(
            secret, ownerPrivLo, ownerPrivHi, newSecret, recipientPubX, recipientPubY, auditPubX, auditPubY
        );

        assertEq(pub.length, 10);
        assertEq(uint256(pub[0]), auditPubX);
        assertEq(uint256(pub[1]), auditPubY);
        assertEq(uint256(pub[2]), apt.roots(apt.currentRootIndex()));

        uint32 beforeNextLeafIndex = apt.nextLeafIndex();

        apt.submitTransfer(
            transferProof,
            AuditablePrivacyTransfer.SubmitTransferParams({
                merkleRoot: uint256(pub[2]),
                transferCommitment: uint256(pub[3]),
                nullifierHash: uint256(pub[4]),
                encryptedRecipientPayload: uint256(pub[5]),
                encryptedAuditPayload: uint256(pub[6]),
                ephemeralPubX: uint256(pub[7]),
                ephemeralPubY: uint256(pub[8]),
                cipherNonce: uint256(pub[9])
            })
        );

        assertTrue(apt.nullifierSpent(uint256(pub[4])));
        assertTrue(apt.commitmentUsed(uint256(pub[3])));
        assertEq(apt.nextLeafIndex(), beforeNextLeafIndex + 1);
        assertTrue(apt.isKnownRoot(apt.roots(apt.currentRootIndex())));

        (uint256 recoveredRecipient, uint256 recoveredAudit) = _decryptTransferPayload(
            recipientPrivLo,
            recipientPrivHi,
            uint256(pub[7]),
            uint256(pub[8]),
            uint256(pub[9]),
            uint256(pub[5]),
            uint256(pub[6])
        );

        assertEq(recoveredRecipient, newSecret);
        assertEq(recoveredAudit, commitment);
    }
}
