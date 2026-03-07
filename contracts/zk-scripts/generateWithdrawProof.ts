import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";
import { execFileSync } from "child_process";
import { AbiCoder, getBytes } from "ethers";
import { Barretenberg, Fr } from "@aztec/bb.js";
import { Noir } from "@noir-lang/noir_js";
import { merkleTree } from "./merkleTree.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const MOD = BigInt("21888242871839275222246405745257275088548364400416034343698204186575808495617");
const NULLIFIER_DOMAIN = "30001";

const withdrawDir = path.resolve(__dirname, "../../circuits/withdraw");
const targetDir = path.join(withdrawDir, "target");
const proverTomlPath = path.join(withdrawDir, "Prover.toml");

const ecdhHelperCircuit = JSON.parse(
  fs.readFileSync(path.resolve(__dirname, "../../circuits/ecdh_helper/target/ecdh_helper.json"), "utf8")
);

const [secret, ownerPrivLo, ownerPrivHi, auditPubX, auditPubY, recipient, commitment] = process.argv.slice(2);
if (!secret || !ownerPrivLo || !ownerPrivHi || !auditPubX || !auditPubY || !recipient || !commitment) {
  console.error(
    "Usage: tsx zk-scripts/generateWithdrawProof.ts <secret> <ownerPrivLo> <ownerPrivHi> <auditPubX> <auditPubY> <recipient> <commitment>"
  );
  process.exit(1);
}

let bbP: Promise<Barretenberg> | undefined;
function toField(v: string) {
  const x = BigInt(v);
  return ((x % MOD) + MOD) % MOD;
}

function toFr(v: string) {
  const n = toField(v);
  let hex = n.toString(16);
  if (hex.length % 2) hex = "0" + hex;
  const src = Buffer.from(hex, "hex");
  const out = Buffer.alloc(32);
  src.copy(out, 32 - src.length);
  return Fr.fromBuffer(out);
}

async function poseidon(values: string[]) {
  if (!bbP) bbP = Barretenberg.new();
  const bb = await bbP;
  const h = await bb.poseidon2Hash(values.map(toFr));
  return h.toString();
}

function split128(x: bigint) {
  const loMask = (BigInt(1) << BigInt(128)) - BigInt(1);
  return {
    lo: (x & loMask).toString(),
    hi: (x >> BigInt(128)).toString(),
  };
}

async function ecdhWithAuditPub(pubX: string, pubY: string, ephLo: string, ephHi: string) {
  const noir = new Noir(ecdhHelperCircuit);
  const { returnValue } = await noir.execute({
    audit_pub_x: pubX,
    audit_pub_y: pubY,
    ephemeral_priv_lo: ephLo,
    ephemeral_priv_hi: ephHi,
  });
  const out = returnValue as unknown as [unknown, unknown, unknown];
  return {
    ephemeralPubX: String(out[0]),
    ephemeralPubY: String(out[1]),
    kAudit: String(out[2]),
  };
}

function writeToml(data: Record<string, string | string[] | boolean[]>) {
  const lines: string[] = [];
  for (const [k, v] of Object.entries(data)) {
    if (Array.isArray(v)) {
      if (typeof v[0] === "boolean") {
        lines.push(`${k} = [${(v as boolean[]).map((x) => (x ? "true" : "false")).join(", ")}]`);
      } else {
        lines.push(`${k} = [${(v as string[]).map((x) => `"${x}"`).join(", ")}]`);
      }
    } else {
      lines.push(`${k} = "${v}"`);
    }
  }
  lines.push("");
  fs.writeFileSync(proverTomlPath, lines.join("\n"), "utf8");
}

function readProofAndInputs() {
  const proof = "0x" + fs.readFileSync(path.join(targetDir, "proof")).toString("hex");
  const raw = fs.readFileSync(path.join(targetDir, "public_inputs"));
  const arr: string[] = [];
  for (let i = 0; i < raw.length; i += 32) {
    arr.push("0x" + raw.subarray(i, i + 32).toString("hex"));
  }
  return { proof, publicInputs: arr };
}

const recipientField = BigInt(recipient).toString();
const eph = (BigInt(secret) + BigInt(ownerPrivLo) + BigInt(ownerPrivHi) + BigInt(90001)) % MOD;
const { lo: ephLo, hi: ephHi } = split128(eph);

const ecdh = await ecdhWithAuditPub(auditPubX, auditPubY, ephLo, ephHi);

const tree = await merkleTree([commitment]);
const proofData = tree.proof(tree.getIndex(commitment));

const nullifierHash = await poseidon([secret, ownerPrivLo, ownerPrivHi, NULLIFIER_DOMAIN]);
const cipherNonce = ((BigInt(secret) ^ BigInt(123456789)) % MOD).toString();
const auditPayload = commitment;
const auditMask = await poseidon([ecdh.kAudit, cipherNonce]);
const encryptedAuditPayload = ((BigInt(auditPayload) + BigInt(auditMask)) % MOD).toString();

writeToml({
  merkle_root: proofData.root,
  audit_pub_x: auditPubX,
  audit_pub_y: auditPubY,
  nullifier_hash: nullifierHash,
  encrypted_audit_payload: encryptedAuditPayload,
  ephemeral_pub_x: ecdh.ephemeralPubX,
  ephemeral_pub_y: ecdh.ephemeralPubY,
  cipher_nonce: cipherNonce,
  recipient: recipientField,
  secret,
  owner_priv_lo: ownerPrivLo,
  owner_priv_hi: ownerPrivHi,
  ephemeral_priv_lo: ephLo,
  ephemeral_priv_hi: ephHi,
  merkle_path: proofData.pathElements,
  merkle_index_bits: proofData.pathIndices.map((x) => x === 1),
});

execFileSync("nargo", ["execute"], { cwd: withdrawDir, stdio: "pipe" });
execFileSync(
  "bb",
  [
    "prove",
    "-b",
    path.join(targetDir, "apt_withdraw.json"),
    "-w",
    path.join(targetDir, "apt_withdraw.gz"),
    "-o",
    targetDir,
    "--write_vk",
    "--verifier_target",
    "evm",
  ],
  { cwd: withdrawDir, stdio: "pipe" }
);

const { proof, publicInputs } = readProofAndInputs();
const encoded = AbiCoder.defaultAbiCoder().encode(["bytes", "bytes32[]"], [getBytes(proof), publicInputs]);
process.stdout.write(encoded);
process.exit(0);
