// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IVerifier} from "./IVerifier.sol";
import {IncrementalMerkleTree} from "./IncrementalMerkleTree.sol";

/// @title AuditablePrivacyTransfer
/// @notice Fixed-denomination privacy pool with auditable transfer and withdraw flows.
contract AuditablePrivacyTransfer is IncrementalMerkleTree {
    error CommitmentAlreadyUsed();
    error InvalidDenomination(uint256 expected, uint256 actual);
    error UnknownMerkleRoot();
    error NullifierAlreadySpent();
    error InvalidProof();
    error InsufficientPoolBalance(uint256 requested, uint256 available);
    error PaymentFailed(address recipient, uint256 amount);

    /// @dev Number of public inputs expected by the deposit circuit.
    uint8 public constant DEPOSIT_PUBLIC_INPUT_COUNT = 1;
    /// @dev Number of public inputs expected by the transfer circuit.
    uint8 public constant TRANSFER_PUBLIC_INPUT_COUNT = 10;
    /// @dev Number of public inputs expected by the withdraw circuit.
    uint8 public constant WITHDRAW_PUBLIC_INPUT_COUNT = 9;
    /// @dev Merkle tree depth used by both contract and circuits.
    uint32 public constant TREE_DEPTH = 20;

    /// @dev Verifier contract for deposit proofs.
    IVerifier public immutable depositVerifier;
    /// @dev Verifier contract for transfer proofs.
    IVerifier public immutable transferVerifier;
    /// @dev Verifier contract for withdraw proofs.
    IVerifier public immutable withdrawVerifier;
    /// @dev Fixed ETH amount for each deposit/withdraw.
    uint256 public immutable denomination;
    /// @dev Long-term audit public key X coordinate.
    uint256 public immutable auditPubX;
    /// @dev Long-term audit public key Y coordinate.
    uint256 public immutable auditPubY;

    /// @dev Tracks whether a nullifier has been spent.
    mapping(uint256 => bool) public nullifierSpent;
    /// @dev Tracks whether a commitment has already been inserted.
    mapping(uint256 => bool) public commitmentUsed;

    struct SubmitTransferParams {
        uint256 merkleRoot;
        uint256 transferCommitment;
        uint256 nullifierHash;
        uint256 encryptedRecipientPayload;
        uint256 encryptedAuditPayload;
        uint256 ephemeralPubX;
        uint256 ephemeralPubY;
        uint256 cipherNonce;
    }

    event DepositSubmitted(address indexed sender, uint256 indexed commitment, uint256 leafIndex, uint256 newRoot);

    event Withdrawal(
        address indexed recipient,
        uint256 indexed nullifierHash,
        uint256 encryptedAuditPayload,
        uint256 ephemeralPubX,
        uint256 ephemeralPubY,
        uint256 cipherNonce,
        uint256 amount,
        uint256 newRoot
    );

    event TransferSubmitted(
        uint256 indexed nullifierHash,
        uint256 indexed transferCommitment,
        uint256 encryptedRecipientPayload,
        uint256 encryptedAuditPayload,
        uint256 ephemeralPubX,
        uint256 ephemeralPubY,
        uint256 cipherNonce,
        uint256 newRoot,
        uint256 leafIndex
    );

    constructor(
        address _depositVerifier,
        address _transferVerifier,
        address _withdrawVerifier,
        address _poseidon2,
        uint256 _denomination,
        uint256 _auditPubX,
        uint256 _auditPubY
    ) IncrementalMerkleTree(TREE_DEPTH, _poseidon2) {
        depositVerifier = IVerifier(_depositVerifier);
        transferVerifier = IVerifier(_transferVerifier);
        withdrawVerifier = IVerifier(_withdrawVerifier);
        denomination = _denomination;
        auditPubX = _auditPubX;
        auditPubY = _auditPubY;
    }

    /// @notice Deposits one fixed denomination and inserts a new commitment.
    /// @param proof ZK proof for deposit circuit.
    /// @param commitment New note commitment to insert.
    function deposit(bytes calldata proof, uint256 commitment) external payable {
        if (commitmentUsed[commitment]) revert CommitmentAlreadyUsed();
        if (msg.value != denomination) revert InvalidDenomination(denomination, msg.value);
        bytes32[] memory publicInputs = new bytes32[](DEPOSIT_PUBLIC_INPUT_COUNT);
        publicInputs[0] = bytes32(commitment);
        if (!depositVerifier.verify(proof, publicInputs)) revert InvalidProof();

        commitmentUsed[commitment] = true;
        uint32 insertedLeafIndex = nextLeafIndex;
        uint256 newRoot = _insertLeaf(commitment);
        emit DepositSubmitted(msg.sender, commitment, insertedLeafIndex, newRoot);
    }

    /// @notice Submits a private transfer that spends one note and creates one new note.
    /// @param proof ZK proof for transfer circuit.
    /// @param params Public transfer values bound by the proof.
    function submitTransfer(bytes calldata proof, SubmitTransferParams calldata params) external {
        if (!isKnownRoot(params.merkleRoot)) revert UnknownMerkleRoot();
        if (nullifierSpent[params.nullifierHash]) revert NullifierAlreadySpent();
        if (commitmentUsed[params.transferCommitment]) revert CommitmentAlreadyUsed();

        bytes32[] memory publicInputs = new bytes32[](TRANSFER_PUBLIC_INPUT_COUNT);
        publicInputs[0] = bytes32(auditPubX);
        publicInputs[1] = bytes32(auditPubY);
        publicInputs[2] = bytes32(params.merkleRoot);
        publicInputs[3] = bytes32(params.transferCommitment);
        publicInputs[4] = bytes32(params.nullifierHash);
        publicInputs[5] = bytes32(params.encryptedRecipientPayload);
        publicInputs[6] = bytes32(params.encryptedAuditPayload);
        publicInputs[7] = bytes32(params.ephemeralPubX);
        publicInputs[8] = bytes32(params.ephemeralPubY);
        publicInputs[9] = bytes32(params.cipherNonce);

        if (!transferVerifier.verify(proof, publicInputs)) revert InvalidProof();

        nullifierSpent[params.nullifierHash] = true;
        commitmentUsed[params.transferCommitment] = true;

        uint32 insertedLeafIndex = nextLeafIndex;
        uint256 newRoot = _insertLeaf(params.transferCommitment);
        emit TransferSubmitted(
            params.nullifierHash,
            params.transferCommitment,
            params.encryptedRecipientPayload,
            params.encryptedAuditPayload,
            params.ephemeralPubX,
            params.ephemeralPubY,
            params.cipherNonce,
            newRoot,
            insertedLeafIndex
        );
    }

    /// @notice Withdraws one fixed denomination to a recipient.
    /// @param proof ZK proof for withdraw circuit.
    /// @param merkleRoot Known root that includes the spent note.
    /// @param nullifierHash Nullifier hash of the spent note.
    /// @param encryptedAuditPayload Encrypted audit payload emitted on-chain.
    /// @param ephemeralPubX Ephemeral public key X for audit decryption.
    /// @param ephemeralPubY Ephemeral public key Y for audit decryption.
    /// @param cipherNonce Nonce used for payload masking.
    /// @param recipient ETH recipient address.
    function withdraw(
        bytes calldata proof,
        uint256 merkleRoot,
        uint256 nullifierHash,
        uint256 encryptedAuditPayload,
        uint256 ephemeralPubX,
        uint256 ephemeralPubY,
        uint256 cipherNonce,
        address payable recipient
    ) external {
        if (!isKnownRoot(merkleRoot)) revert UnknownMerkleRoot();
        if (nullifierSpent[nullifierHash]) revert NullifierAlreadySpent();
        if (denomination > address(this).balance) revert InsufficientPoolBalance(denomination, address(this).balance);

        bytes32[] memory publicInputs = new bytes32[](WITHDRAW_PUBLIC_INPUT_COUNT);
        publicInputs[0] = bytes32(merkleRoot);
        publicInputs[1] = bytes32(auditPubX);
        publicInputs[2] = bytes32(auditPubY);
        publicInputs[3] = bytes32(nullifierHash);
        publicInputs[4] = bytes32(encryptedAuditPayload);
        publicInputs[5] = bytes32(ephemeralPubX);
        publicInputs[6] = bytes32(ephemeralPubY);
        publicInputs[7] = bytes32(cipherNonce);
        publicInputs[8] = bytes32(uint256(uint160(address(recipient))));

        bool ok = withdrawVerifier.verify(proof, publicInputs);
        if (!ok) revert InvalidProof();

        nullifierSpent[nullifierHash] = true;
        uint256 newRoot = roots[currentRootIndex];

        (bool sent,) = recipient.call{value: denomination}("");
        if (!sent) revert PaymentFailed(recipient, denomination);

        emit Withdrawal(
            recipient,
            nullifierHash,
            encryptedAuditPayload,
            ephemeralPubX,
            ephemeralPubY,
            cipherNonce,
            denomination,
            newRoot
        );
    }
}
