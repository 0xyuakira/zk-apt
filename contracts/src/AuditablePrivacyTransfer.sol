// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IVerifier} from "./Verifier.sol";
import {IncrementalMerkleTree} from "./IncrementalMerkleTree.sol";

contract AuditablePrivacyTransfer is IncrementalMerkleTree {
    error CommitmentAlreadyUsed();
    error InvalidDenomination(uint256 expected, uint256 actual);
    error UnknownMerkleRoot();
    error NullifierAlreadySpent();
    error InvalidProof();
    error InsufficientPoolBalance(uint256 requested, uint256 available);
    error PaymentFailed(address recipient, uint256 amount);

    uint8 public constant TRANSFER_PUBLIC_INPUT_COUNT = 11;
    uint8 public constant WITHDRAW_PUBLIC_INPUT_COUNT = 8;

    IVerifier public immutable verifier;
    uint256 public immutable denomination;
    uint256 public immutable auditPub;

    mapping(uint256 => bool) public nullifierSpent;
    mapping(uint256 => bool) public commitmentUsed;

    struct SubmitTransferParams {
        uint256 merkleRoot;
        uint256 transferCommitment;
        uint256 nullifierHash;
        uint256 encryptedNoteDataReceiver;
        uint256 encryptedNoteDataAudit;
        uint256 receiverEphemeralPubX;
        uint256 receiverEphemeralPubY;
        uint256 auditEphemeralPubX;
        uint256 auditEphemeralPubY;
        uint256 cipherNonce;
    }

    event DepositSubmitted(address indexed sender, uint256 indexed commitment, uint256 leafIndex, uint256 newRoot);

    event Withdrawal(
        address indexed recipient,
        uint256 indexed nullifierHash,
        uint256 encryptedAuditPayload,
        uint256 auditEphemeralPubX,
        uint256 auditEphemeralPubY,
        uint256 cipherNonce,
        uint256 amount,
        uint256 newRoot
    );

    event TransferSubmitted(
        uint256 indexed nullifierHash,
        uint256 indexed transferCommitment,
        uint256 encryptedNoteDataReceiver,
        uint256 encryptedNoteDataAudit,
        uint256 receiverEphemeralPubX,
        uint256 receiverEphemeralPubY,
        uint256 auditEphemeralPubX,
        uint256 auditEphemeralPubY,
        uint256 cipherNonce,
        uint256 newRoot,
        uint256 leafIndex
    );

    constructor(uint32 _treeDepth, address _verifier, address _poseidon2, uint256 _denomination, uint256 _auditPub)
        IncrementalMerkleTree(_treeDepth, _poseidon2)
    {
        verifier = IVerifier(_verifier);
        denomination = _denomination;
        auditPub = _auditPub;
    }

    function deposit(uint256 commitment) external payable {
        if (commitmentUsed[commitment]) revert CommitmentAlreadyUsed();
        if (msg.value != denomination) revert InvalidDenomination(denomination, msg.value);

        commitmentUsed[commitment] = true;
        uint32 insertedLeafIndex = nextLeafIndex;
        uint256 newRoot = _insertLeaf(commitment);
        emit DepositSubmitted(msg.sender, commitment, insertedLeafIndex, newRoot);
    }

    function submitTransfer(bytes calldata proof, SubmitTransferParams calldata params) external {
        if (!isKnownRoot(params.merkleRoot)) revert UnknownMerkleRoot();
        if (nullifierSpent[params.nullifierHash]) revert NullifierAlreadySpent();
        if (commitmentUsed[params.transferCommitment]) revert CommitmentAlreadyUsed();

        bytes32[] memory publicInputs = new bytes32[](TRANSFER_PUBLIC_INPUT_COUNT);
        publicInputs[0] = bytes32(auditPub);
        publicInputs[1] = bytes32(params.merkleRoot);
        publicInputs[2] = bytes32(params.transferCommitment);
        publicInputs[3] = bytes32(params.nullifierHash);
        publicInputs[4] = bytes32(params.encryptedNoteDataReceiver);
        publicInputs[5] = bytes32(params.encryptedNoteDataAudit);
        publicInputs[6] = bytes32(params.receiverEphemeralPubX);
        publicInputs[7] = bytes32(params.receiverEphemeralPubY);
        publicInputs[8] = bytes32(params.auditEphemeralPubX);
        publicInputs[9] = bytes32(params.auditEphemeralPubY);
        publicInputs[10] = bytes32(params.cipherNonce);

        if (!verifier.verify(proof, publicInputs)) revert InvalidProof();

        nullifierSpent[params.nullifierHash] = true;
        commitmentUsed[params.transferCommitment] = true;

        uint32 insertedLeafIndex = nextLeafIndex;
        uint256 newRoot = _insertLeaf(params.transferCommitment);
        emit TransferSubmitted(
            params.nullifierHash,
            params.transferCommitment,
            params.encryptedNoteDataReceiver,
            params.encryptedNoteDataAudit,
            params.receiverEphemeralPubX,
            params.receiverEphemeralPubY,
            params.auditEphemeralPubX,
            params.auditEphemeralPubY,
            params.cipherNonce,
            newRoot,
            insertedLeafIndex
        );
    }

    function withdraw(
        bytes calldata proof,
        uint256 merkleRoot,
        uint256 nullifierHash,
        uint256 encryptedAuditPayload,
        uint256 auditEphemeralPubX,
        uint256 auditEphemeralPubY,
        uint256 cipherNonce,
        address payable recipient
    ) external {
        if (!isKnownRoot(merkleRoot)) revert UnknownMerkleRoot();
        if (nullifierSpent[nullifierHash]) revert NullifierAlreadySpent();
        if (denomination > address(this).balance) revert InsufficientPoolBalance(denomination, address(this).balance);

        bytes32[] memory publicInputs = new bytes32[](WITHDRAW_PUBLIC_INPUT_COUNT);
        publicInputs[0] = bytes32(merkleRoot);
        publicInputs[1] = bytes32(auditPub);
        publicInputs[2] = bytes32(nullifierHash);
        publicInputs[3] = bytes32(encryptedAuditPayload);
        publicInputs[4] = bytes32(auditEphemeralPubX);
        publicInputs[5] = bytes32(auditEphemeralPubY);
        publicInputs[6] = bytes32(cipherNonce);
        publicInputs[7] = bytes32(uint256(uint160(address(recipient))));

        bool ok = verifier.verify(proof, publicInputs);
        if (!ok) revert InvalidProof();

        nullifierSpent[nullifierHash] = true;
        uint256 newRoot = roots[currentRootIndex];

        (bool sent,) = recipient.call{value: denomination}("");
        if (!sent) revert PaymentFailed(recipient, denomination);

        emit Withdrawal(
            recipient,
            nullifierHash,
            encryptedAuditPayload,
            auditEphemeralPubX,
            auditEphemeralPubY,
            cipherNonce,
            denomination,
            newRoot
        );
    }
}
