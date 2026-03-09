# zk-apt
### ZK Auditable Privacy Transfer Protocol

[中文版本](./README.md)

A privacy-preserving transfer protocol with selective auditability, built with zero-knowledge proofs (ZK).
It uses Noir circuits to constrain transaction validity and smart contracts for on-chain verification and state updates.

`zk-apt` is not just an anonymity demo. It is designed to deliver all three together:
- ZK circuit soundness (provable correctness)
- Private transfer semantics (practical usability)
- Audit channel semantics (decryptable and traceable by a designated auditor)

---

## Motivation
Pure privacy systems are often insufficient in real-world settings:
- users need privacy
- compliance/risk systems still need verifiable audit trails

`zk-apt` implements **selective auditability**:
- normal observers cannot see transfer semantics in plaintext
- a designated auditor can decrypt the audit channel and recover traceable linkage

---

## Core Design

### 1) Three Circuits
- `deposit`: creates a note commitment and constrains commitment correctness in-circuit
- `transfer`: spends an old note, creates a new note, and constrains recipient/audit ciphertexts in-circuit
- `withdraw`: exits from the shielded pool to a public recipient with constrained audit ciphertext

### 2) On-Chain Verification and State Management
`AuditablePrivacyTransfer.sol` handles:
- proof verification
- nullifier set updates (double-spend prevention)
- merkle root history updates
- commitment set updates

### 3) In-Circuit Encryption Consistency
Ciphertexts are not arbitrary off-chain metadata; they are constrained in-circuit:
- ephemeral public key consistency
- ECDH shared key consistency
- ciphertext = plaintext + mask consistency

So a proof is valid only if ciphertexts satisfy protocol constraints.

---

## Flow

### Deposit
1. User prepares `(secret, owner_pub)`
2. Compute note commitment (Poseidon2)
3. Generate `deposit` proof
4. Contract verifies and inserts commitment into merkle tree

### Transfer
1. Sender proves old note membership + nullifier correctness
2. Create a new note for recipient
3. Circuit constrains recipient/audit ciphertext channels
4. Contract verifies, marks nullifier spent, and inserts new commitment

Transfer’s core challenge is **ownership handoff**, not just writing a new commitment.
The new commitment binds spend authority to the recipient public key.
When spending this new note later, correct nullifier construction requires recipient-private-key-related witness data.
Even if the sender knows old note data and transfer parameters, they cannot forge recipient-private-key witness and therefore cannot spend the recipient’s new note.

### Withdraw
1. Owner proves note membership and spend authorization
2. Circuit constrains withdraw public inputs and audit ciphertext
3. Contract verifies and transfers fixed denomination to recipient

---

## Security Properties
- **Double-spend resistance**: nullifier set
- **Membership soundness**: merkle path constraints
- **Commitment integrity**: in-circuit commitment constraints
- **Ciphertext integrity**: in-circuit ciphertext constraints
- **Selective auditability**: dedicated encrypted audit channel

---

## Quick Start

### Environment (Pinned Versions Recommended)
- Node.js: `v22.22.0`
- nargo / noirc: `1.0.0-beta.19`
- bb CLI: `4.0.0-nightly.20260120`
- Solidity: `0.8.27`
- Foundry: `1.5.1-stable`

### Install script dependencies
```bash
cd contracts/zk-scripts
npm install
```

### Compile circuits
```bash
cd ../../circuits/deposit && nargo compile
cd ../transfer && nargo compile
cd ../withdraw && nargo compile
cd ../keygen && nargo compile
cd ../ecdh_helper && nargo compile
```

### Run tests (serial recommended)
```bash
cd ../../contracts
forge test --jobs 1
```
---