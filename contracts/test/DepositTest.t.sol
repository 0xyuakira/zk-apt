// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";
import {HonkVerifier as DepositHonkVerifier} from "../src/verifiers/deposit/Verifier.sol";
import {HonkVerifier as TransferHonkVerifier} from "../src/verifiers/transfer/Verifier.sol";
import {HonkVerifier as WithdrawHonkVerifier} from "../src/verifiers/withdraw/Verifier.sol";
import {AuditablePrivacyTransfer} from "../src/AuditablePrivacyTransfer.sol";
import {Poseidon2} from "../src/IncrementalMerkleTree.sol";
import {Field} from "poseidon2-evm/Field.sol";

contract DepositTest is Test {
    DepositHonkVerifier public depositVerifier;
    TransferHonkVerifier public transferVerifier;
    WithdrawHonkVerifier public withdrawVerifier;

    AuditablePrivacyTransfer public apt;
    Poseidon2 public poseidon;

    uint256 constant BN254_R = 21888242871839275222246405745257275088548364400416034343698204186575808495617;
    uint256 constant NOTE_COMMITMENT_DOMAIN = 20_001;

    function setUp() public {
        depositVerifier = new DepositHonkVerifier();
        transferVerifier = new TransferHonkVerifier();
        withdrawVerifier = new WithdrawHonkVerifier();
        poseidon = new Poseidon2();

        apt = new AuditablePrivacyTransfer(
            address(depositVerifier),
            address(transferVerifier),
            address(withdrawVerifier),
            address(poseidon),
            1 ether,
            0,
            0
        );
    }

    function _getKeyPair() internal returns (uint256 privLo, uint256 privHi, uint256 pubX, uint256 pubY) {
        uint256 priv = uint256(keccak256(abi.encodePacked(address(this), block.chainid))) % BN254_R;
        privLo = uint128(priv);
        privHi = uint128(priv >> 128);

        string[] memory inputs = new string[](5);
        inputs[0] = "npx";
        inputs[1] = "tsx";
        inputs[2] = "scripts/generatePubKey.ts";
        inputs[3] = vm.toString(privLo);
        inputs[4] = vm.toString(privHi);

        (, bytes32[] memory publicInputs) = abi.decode(vm.ffi(inputs), (bytes, bytes32[]));
        pubX = uint256(publicInputs[0]);
        pubY = uint256(publicInputs[1]);
    }

    function _generateDepositProof(
        uint256 commitment,
        uint256 secret,
        uint256 ownerPrivLo,
        uint256 ownerPrivHi,
        uint256 ownerPubX,
        uint256 ownerPubY
    ) internal returns (bytes memory proof, bytes32[] memory publicInputs) {
        string[] memory inputs = new string[](9);
        inputs[0] = "npx";
        inputs[1] = "tsx";
        inputs[2] = "scripts/generateDepositProof.ts";
        //public inputs
        inputs[3] = vm.toString(commitment);
        //private inputs
        inputs[4] = vm.toString(secret);
        inputs[5] = vm.toString(ownerPrivLo);
        inputs[6] = vm.toString(ownerPrivHi);
        inputs[7] = vm.toString(ownerPubX);
        inputs[8] = vm.toString(ownerPubY);

        return abi.decode(vm.ffi(inputs), (bytes, bytes32[]));
    }

    function _getCommitment(uint256 secret, uint256 pubX, uint256 pubY) internal view returns (uint256) {
        Field.Type[] memory input = new Field.Type[](4);
        input[0] = Field.toField(secret);
        input[1] = Field.toField(pubX);
        input[2] = Field.toField(pubY);
        input[3] = Field.toField(NOTE_COMMITMENT_DOMAIN);
        return Field.toUint256(poseidon.hash(input));
    }

    function testGetPubKey() public {
        (,, uint256 pubX, uint256 pubY) = _getKeyPair();
        console.log("Public Key X:", pubX);
        console.log("Public Key Y:", pubY);
        assertTrue(pubX != 0);
        assertTrue(pubY != 0);
    }

    function testComputeCommitmentFromContractPoseidon() public {
        (,, uint256 pubX, uint256 pubY) = _getKeyPair();
        uint256 secret = uint256(keccak256(abi.encodePacked("deposit-secret"))) % BN254_R;
        if (secret == 0) secret = 1;

        uint256 commitmentA = _getCommitment(secret, pubX, pubY);
        uint256 commitmentB = _getCommitment(secret, pubX, pubY);

        assertEq(commitmentA, commitmentB);
        assertTrue(commitmentA < BN254_R);
    }

    function testDepositWithRealProofViaFFI() public {
        (uint256 privLo, uint256 privHi, uint256 pubX, uint256 pubY) = _getKeyPair();
        uint256 secret = uint256(keccak256(abi.encodePacked("deposit-real-proof", block.timestamp))) % BN254_R;

        uint256 commitment = _getCommitment(secret, pubX, pubY);
        (bytes memory proof, bytes32[] memory publicInputs) =
            _generateDepositProof(commitment, secret, privLo, privHi, pubX, pubY);

        assertEq(publicInputs.length, 1);
        assertEq(uint256(publicInputs[0]), commitment);

        uint32 beforeNextLeafIndex = apt.nextLeafIndex();
        uint32 beforeRootIndex = apt.currentRootIndex();
        uint256 beforeRoot = apt.roots(beforeRootIndex);

        apt.deposit{value: 1 ether}(proof, commitment);

        uint32 afterNextLeafIndex = apt.nextLeafIndex();
        uint32 afterRootIndex = apt.currentRootIndex();
        uint256 afterRoot = apt.roots(afterRootIndex);

        // Commitment should be inserted into the incremental Merkle tree.
        assertEq(afterNextLeafIndex, beforeNextLeafIndex + 1);
        assertTrue(apt.isKnownRoot(afterRoot));
        assertTrue(afterRoot != 0);
        assertTrue(afterRoot != beforeRoot);

        assertTrue(apt.commitmentUsed(commitment));
    }
}
