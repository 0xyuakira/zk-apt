import { AbiCoder } from "ethers";
import { Noir } from "@noir-lang/noir_js";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";
import { Barretenberg, Fr } from "@aztec/bb.js";

const MOD = BigInt("21888242871839275222246405745257275088548364400416034343698204186575808495617");

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const ecdhHelperCircuit = JSON.parse(
  fs.readFileSync(path.resolve(__dirname, "../../circuits/ecdh_helper/target/ecdh_helper.json"), "utf8")
);

const [auditPrivLo, auditPrivHi, ephemeralPubX, ephemeralPubY, cipherNonce, encryptedAuditPayload] =
  process.argv.slice(2);

if (!auditPrivLo || !auditPrivHi || !ephemeralPubX || !ephemeralPubY || !cipherNonce || !encryptedAuditPayload) {
  console.error(
    "Usage: tsx zk-scripts/decryptWithdrawPayload.ts <auditPrivLo> <auditPrivHi> <ephemeralPubX> <ephemeralPubY> <cipherNonce> <encryptedAuditPayload>"
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

async function sharedKeyFromPub(pubX: string, pubY: string, privLo: string, privHi: string) {
  const noir = new Noir(ecdhHelperCircuit);
  const { returnValue } = await noir.execute({
    audit_pub_x: pubX,
    audit_pub_y: pubY,
    ephemeral_priv_lo: privLo,
    ephemeral_priv_hi: privHi,
  });
  const out = returnValue as unknown as [unknown, unknown, unknown];
  return String(out[2]);
}

const kAudit = await sharedKeyFromPub(ephemeralPubX, ephemeralPubY, auditPrivLo, auditPrivHi);
const auditMask = await poseidon([kAudit, cipherNonce]);
const recoveredAuditPayload = (toField(encryptedAuditPayload) - toField(auditMask) + MOD) % MOD;

const encoded = AbiCoder.defaultAbiCoder().encode(["uint256"], [recoveredAuditPayload.toString()]);
process.stdout.write(encoded);
process.exit(0);
