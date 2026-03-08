// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {AptTestBase} from "./AptTestBase.t.sol";

contract WithdrawTest is AptTestBase {
    function testWithdrawWithRealProofViaFFI() public {
        (uint256 ownerPrivLo, uint256 ownerPrivHi, uint256 ownerPubX, uint256 ownerPubY) =
            _getKeyPair(uint256(keccak256("withdraw-user")));

        uint256 seed = uint256(keccak256(abi.encodePacked("withdraw-real-proof", block.timestamp)));
        uint256 secret;
        uint256 commitment;

        secret = uint256(keccak256(abi.encodePacked(seed))) % BN254_R;
        commitment = _getCommitment(secret, ownerPubX, ownerPubY);

        (bytes memory depositProof,) = _generateDepositProof(commitment, secret, ownerPrivLo, ownerPrivHi);
        apt.deposit{value: 1 ether}(depositProof, commitment);

        address payable recipient = payable(makeAddr("recipient"));
        uint256 recipientBefore = recipient.balance;
        uint256 poolBefore = address(apt).balance;

        (bytes memory withdrawProof, bytes32[] memory pub) =
            _generateWithdrawProof(secret, ownerPrivLo, ownerPrivHi, auditPubX, auditPubY, recipient, commitment);

        assertEq(pub.length, 9);
        assertEq(uint256(pub[1]), auditPubX);
        assertEq(uint256(pub[2]), auditPubY);
        assertEq(uint256(pub[8]), uint256(uint160(address(recipient))));

        apt.withdraw(
            withdrawProof,
            uint256(pub[0]),
            uint256(pub[3]),
            uint256(pub[4]),
            uint256(pub[5]),
            uint256(pub[6]),
            uint256(pub[7]),
            recipient
        );

        assertEq(recipient.balance, recipientBefore + 1 ether);
        assertEq(address(apt).balance, poolBefore - 1 ether);
        assertTrue(apt.nullifierSpent(uint256(pub[3])));

        uint256 recoveredAuditPayload =
            _decryptWithdrawAuditPayload(uint256(pub[5]), uint256(pub[6]), uint256(pub[7]), uint256(pub[4]));
        assertEq(recoveredAuditPayload, commitment);
    }
}
