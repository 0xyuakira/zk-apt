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

    uint8 public constant TRANSFER_PUBLIC_INPUT_COUNT = 12;
    uint8 public constant WITHDRAW_PUBLIC_INPUT_COUNT = 4;

    IVerifier public immutable verifier;
    uint256 public immutable denomination;
    uint256 public immutable auditPub;

    mapping(uint256 => bool) public nullifierSpent;
    mapping(uint256 => bool) public commitmentUsed;
    struct SubmitTransferParams {
        uint256 receiverPub;
        uint256 merkleRoot;
        uint256 transferCommitment;
        uint256 nullifier;
        uint256 encryptedNoteDataReceiver;
        uint256 encryptedNoteDataAudit;
        uint256 receiverEphemeralPubX;
        uint256 receiverEphemeralPubY;
        uint256 auditEphemeralPubX;
        uint256 auditEphemeralPubY;
        uint256 cipherNonce;
    }

    event DepositSubmitted(
        address indexed sender,
        uint256 indexed coinCommitment,
        uint256 leafIndex,
        uint256 newRoot,
        uint256 amount
    );

    event Withdrawal(
        address indexed recipient,
        uint256 indexed nullifier,
        uint256 amount,
        uint256 newRoot
    );

    event TransferSubmitted(
        uint256 indexed nullifier,
        uint256 indexed transferCommitment,
        uint256 encryptedNoteDataReceiver,
        uint256 encryptedNoteDataAudit,
        uint256 receiverEphemeralPubX,
        uint256 receiverEphemeralPubY,
        uint256 auditEphemeralPubX,
        uint256 auditEphemeralPubY,
        uint256 cipherNonce,
        uint256 newRoot
    );

    constructor(uint32 _treeDepth, address _verifier, address _poseidon2, uint256 _denomination, uint256 _auditPub)
        IncrementalMerkleTree(_treeDepth, _poseidon2)
    {
        verifier = IVerifier(_verifier);
        denomination = _denomination;
        auditPub = _auditPub;
    }

    function deposit(uint256 coinCommitment) external payable returns (uint256 insertedLeafIndex) {
        if (commitmentUsed[coinCommitment]) revert CommitmentAlreadyUsed();
        if (msg.value != denomination) revert InvalidDenomination(denomination, msg.value);

        insertedLeafIndex = nextLeafIndex;
        commitmentUsed[coinCommitment] = true;
        uint256 newRoot = _insertLeaf(coinCommitment);
        emit DepositSubmitted(msg.sender, coinCommitment, insertedLeafIndex, newRoot, msg.value);
    }

    function submitTransfer(bytes calldata proof, SubmitTransferParams calldata params) external {
        if (!isKnownRoot(params.merkleRoot)) revert UnknownMerkleRoot();
        if (nullifierSpent[params.nullifier]) revert NullifierAlreadySpent();
        if (commitmentUsed[params.transferCommitment]) revert CommitmentAlreadyUsed();

        bytes32[] memory publicInputs = new bytes32[](TRANSFER_PUBLIC_INPUT_COUNT);
        publicInputs[0] = bytes32(params.receiverPub);
        publicInputs[1] = bytes32(auditPub);
        publicInputs[2] = bytes32(params.merkleRoot);
        publicInputs[3] = bytes32(params.transferCommitment);
        publicInputs[4] = bytes32(params.nullifier);
        publicInputs[5] = bytes32(params.encryptedNoteDataReceiver);
        publicInputs[6] = bytes32(params.encryptedNoteDataAudit);
        publicInputs[7] = bytes32(params.receiverEphemeralPubX);
        publicInputs[8] = bytes32(params.receiverEphemeralPubY);
        publicInputs[9] = bytes32(params.auditEphemeralPubX);
        publicInputs[10] = bytes32(params.auditEphemeralPubY);
        publicInputs[11] = bytes32(params.cipherNonce);

        if (!verifier.verify(proof, publicInputs)) revert InvalidProof();

        nullifierSpent[params.nullifier] = true;
        commitmentUsed[params.transferCommitment] = true;

        uint256 newRoot = _insertLeaf(params.transferCommitment);
        emit TransferSubmitted(
            params.nullifier,
            params.transferCommitment,
            params.encryptedNoteDataReceiver,
            params.encryptedNoteDataAudit,
            params.receiverEphemeralPubX,
            params.receiverEphemeralPubY,
            params.auditEphemeralPubX,
            params.auditEphemeralPubY,
            params.cipherNonce,
            newRoot
        );
    }

    function withdraw(
        bytes calldata proof,
        uint256 merkleRoot,
        uint256 nullifier,
        uint256 encryptedNoteDataAudit,
        address payable recipient
    ) external {
        if (!isKnownRoot(merkleRoot)) revert UnknownMerkleRoot();
        if (nullifierSpent[nullifier]) revert NullifierAlreadySpent();
        if (denomination > address(this).balance) revert InsufficientPoolBalance(denomination, address(this).balance);

        bytes32[] memory publicInputs = new bytes32[](WITHDRAW_PUBLIC_INPUT_COUNT);
        publicInputs[0] = bytes32(merkleRoot);
        publicInputs[1] = bytes32(nullifier);
        publicInputs[2] = bytes32(encryptedNoteDataAudit);
        publicInputs[3] = bytes32(uint256(uint160(address(recipient))));

        bool ok = verifier.verify(proof, publicInputs);
        if (!ok) revert InvalidProof();

        nullifierSpent[nullifier] = true;
        uint256 newRoot = roots[currentRootIndex];

        (bool sent,) = recipient.call{value: denomination}("");
        if (!sent) revert PaymentFailed(recipient, denomination);

        emit Withdrawal(recipient, nullifier, denomination, newRoot);
    }
}
