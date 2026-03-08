// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {HonkVerifier as DepositHonkVerifier} from "../src/verifiers/deposit/Verifier.sol";
import {HonkVerifier as TransferHonkVerifier} from "../src/verifiers/transfer/Verifier.sol";
import {HonkVerifier as WithdrawHonkVerifier} from "../src/verifiers/withdraw/Verifier.sol";
import {AuditablePrivacyTransfer} from "../src/AuditablePrivacyTransfer.sol";
import {Poseidon2} from "../src/IncrementalMerkleTree.sol";
import {Field} from "poseidon2-evm/Field.sol";

abstract contract AptTestBase is Test {
    DepositHonkVerifier public depositVerifier;
    TransferHonkVerifier public transferVerifier;
    WithdrawHonkVerifier public withdrawVerifier;

    AuditablePrivacyTransfer public apt;
    Poseidon2 public poseidon;

    uint256 internal auditPrivLo;
    uint256 internal auditPrivHi;
    uint256 internal auditPubX;
    uint256 internal auditPubY;

    uint256 internal constant BN254_R = 21888242871839275222246405745257275088548364400416034343698204186575808495617;
    uint256 internal constant NOTE_COMMITMENT_DOMAIN = 20_001;

    function setUp() public virtual {
        (auditPrivLo, auditPrivHi, auditPubX, auditPubY) = _getKeyPair(uint256(keccak256("audit-key")));

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
            auditPubX,
            auditPubY
        );
    }

    function _getKeyPair(uint256 salt) internal returns (uint256 privLo, uint256 privHi, uint256 pubX, uint256 pubY) {
        uint256 priv = uint256(keccak256(abi.encodePacked(address(this), block.chainid, salt))) % BN254_R;
        if (priv == 0) priv = 1;
        privLo = uint128(priv);
        privHi = uint128(priv >> 128);

        string[] memory inputs = new string[](5);
        inputs[0] = "npx";
        inputs[1] = "tsx";
        inputs[2] = "zk-scripts/generatePubKey.ts";
        inputs[3] = vm.toString(privLo);
        inputs[4] = vm.toString(privHi);

        (, bytes32[] memory publicInputs) = abi.decode(vm.ffi(inputs), (bytes, bytes32[]));
        pubX = uint256(publicInputs[0]);
        pubY = uint256(publicInputs[1]);
    }

    function _getCommitment(uint256 secret, uint256 pubX, uint256 pubY) internal view returns (uint256) {
        Field.Type[] memory input = new Field.Type[](4);
        input[0] = Field.toField(secret);
        input[1] = Field.toField(pubX);
        input[2] = Field.toField(pubY);
        input[3] = Field.toField(NOTE_COMMITMENT_DOMAIN);
        return Field.toUint256(poseidon.hash(input));
    }

    function _generateDepositProof(uint256 commitment, uint256 secret, uint256 ownerPrivLo, uint256 ownerPrivHi)
        internal
        returns (bytes memory proof, bytes32[] memory publicInputs)
    {
        string[] memory inputs = new string[](7);
        inputs[0] = "npx";
        inputs[1] = "tsx";
        inputs[2] = "zk-scripts/generateDepositProof.ts";
        inputs[3] = vm.toString(commitment);
        inputs[4] = vm.toString(secret);
        inputs[5] = vm.toString(ownerPrivLo);
        inputs[6] = vm.toString(ownerPrivHi);

        return abi.decode(vm.ffi(inputs), (bytes, bytes32[]));
    }

    function _generateWithdrawProof(
        uint256 secret,
        uint256 ownerPrivLo,
        uint256 ownerPrivHi,
        uint256 _auditPubX,
        uint256 _auditPubY,
        address recipient,
        uint256 commitment
    ) internal returns (bytes memory proof, bytes32[] memory publicInputs) {
        string[] memory inputs = new string[](10);
        inputs[0] = "npx";
        inputs[1] = "tsx";
        inputs[2] = "zk-scripts/generateWithdrawProof.ts";
        inputs[3] = vm.toString(secret);
        inputs[4] = vm.toString(ownerPrivLo);
        inputs[5] = vm.toString(ownerPrivHi);
        inputs[6] = vm.toString(_auditPubX);
        inputs[7] = vm.toString(_auditPubY);
        inputs[8] = vm.toString(uint256(uint160(recipient)));
        inputs[9] = vm.toString(commitment);

        return abi.decode(vm.ffi(inputs), (bytes, bytes32[]));
    }

    function _generateTransferProof(
        uint256 secret,
        uint256 ownerPrivLo,
        uint256 ownerPrivHi,
        uint256 newSecret,
        uint256 recipientPubX,
        uint256 recipientPubY,
        uint256 _auditPubX,
        uint256 _auditPubY
    ) internal returns (bytes memory proof, bytes32[] memory publicInputs) {
        string[] memory inputs = new string[](11);
        inputs[0] = "npx";
        inputs[1] = "tsx";
        inputs[2] = "zk-scripts/generateTransferProof.ts";
        inputs[3] = vm.toString(secret);
        inputs[4] = vm.toString(ownerPrivLo);
        inputs[5] = vm.toString(ownerPrivHi);
        inputs[6] = vm.toString(newSecret);
        inputs[7] = vm.toString(recipientPubX);
        inputs[8] = vm.toString(recipientPubY);
        inputs[9] = vm.toString(_auditPubX);
        inputs[10] = vm.toString(_auditPubY);

        return abi.decode(vm.ffi(inputs), (bytes, bytes32[]));
    }

    function _decryptTransferPayload(
        uint256 recipientPrivLo,
        uint256 recipientPrivHi,
        uint256 ephemeralPubX,
        uint256 ephemeralPubY,
        uint256 cipherNonce,
        uint256 encryptedRecipientPayload,
        uint256 encryptedAuditPayload
    ) internal returns (uint256 recoveredRecipient, uint256 recoveredAudit) {
        string[] memory inputs = new string[](12);
        inputs[0] = "npx";
        inputs[1] = "tsx";
        inputs[2] = "zk-scripts/decryptTransferPayload.ts";
        inputs[3] = vm.toString(recipientPrivLo);
        inputs[4] = vm.toString(recipientPrivHi);
        inputs[5] = vm.toString(auditPrivLo);
        inputs[6] = vm.toString(auditPrivHi);
        inputs[7] = vm.toString(ephemeralPubX);
        inputs[8] = vm.toString(ephemeralPubY);
        inputs[9] = vm.toString(cipherNonce);
        inputs[10] = vm.toString(encryptedRecipientPayload);
        inputs[11] = vm.toString(encryptedAuditPayload);

        return abi.decode(vm.ffi(inputs), (uint256, uint256));
    }

    function _decryptWithdrawAuditPayload(
        uint256 ephemeralPubX,
        uint256 ephemeralPubY,
        uint256 cipherNonce,
        uint256 encryptedAuditPayload
    ) internal returns (uint256 recoveredAuditPayload) {
        string[] memory inputs = new string[](9);
        inputs[0] = "npx";
        inputs[1] = "tsx";
        inputs[2] = "zk-scripts/decryptWithdrawPayload.ts";
        inputs[3] = vm.toString(auditPrivLo);
        inputs[4] = vm.toString(auditPrivHi);
        inputs[5] = vm.toString(ephemeralPubX);
        inputs[6] = vm.toString(ephemeralPubY);
        inputs[7] = vm.toString(cipherNonce);
        inputs[8] = vm.toString(encryptedAuditPayload);

        return abi.decode(vm.ffi(inputs), (uint256));
    }
}
