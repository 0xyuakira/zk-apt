// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {console} from "forge-std/Test.sol";
import {AptTestBase} from "./AptTestBase.t.sol";

contract DepositTest is AptTestBase {
    function testGetPubKey() public {
        (,, uint256 pubX, uint256 pubY) = _getKeyPair(1);
        console.log("Public Key X:", pubX);
        console.log("Public Key Y:", pubY);
        assertTrue(pubX != 0);
        assertTrue(pubY != 0);
    }

    function testComputeCommitmentFromContractPoseidon() public {
        (,, uint256 pubX, uint256 pubY) = _getKeyPair(2);
        uint256 secret = uint256(keccak256(abi.encodePacked("deposit-secret"))) % BN254_R;

        uint256 commitmentA = _getCommitment(secret, pubX, pubY);
        uint256 commitmentB = _getCommitment(secret, pubX, pubY);

        assertEq(commitmentA, commitmentB);
        assertTrue(commitmentA < BN254_R);
    }

    function testDepositWithRealProofViaFFI() public {
        (uint256 privLo, uint256 privHi, uint256 pubX, uint256 pubY) = _getKeyPair(uint256(keccak256("deposit-user")));

        uint256 seed = uint256(keccak256(abi.encodePacked("deposit-real-proof", block.timestamp)));
        uint256 secret;
        uint256 commitment;

        secret = uint256(keccak256(abi.encodePacked(seed))) % BN254_R;
        commitment = _getCommitment(secret, pubX, pubY);

        (bytes memory proof, bytes32[] memory publicInputs) = _generateDepositProof(commitment, secret, privLo, privHi);

        assertEq(publicInputs.length, 1);
        assertEq(uint256(publicInputs[0]), commitment);

        uint32 beforeNextLeafIndex = apt.nextLeafIndex();
        uint32 beforeRootIndex = apt.currentRootIndex();
        uint256 beforeRoot = apt.roots(beforeRootIndex);

        apt.deposit{value: 1 ether}(proof, commitment);

        uint32 afterNextLeafIndex = apt.nextLeafIndex();
        uint32 afterRootIndex = apt.currentRootIndex();
        uint256 afterRoot = apt.roots(afterRootIndex);

        assertEq(afterNextLeafIndex, beforeNextLeafIndex + 1);
        assertTrue(apt.isKnownRoot(afterRoot));
        assertTrue(afterRoot != 0);
        assertTrue(afterRoot != beforeRoot);
        assertTrue(apt.commitmentUsed(commitment));
    }
}
