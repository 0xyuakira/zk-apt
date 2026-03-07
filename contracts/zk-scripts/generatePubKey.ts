import { ethers } from "ethers";
import { Noir } from "@noir-lang/noir_js";
import path from "path";
import fs from "fs";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const circuit = JSON.parse(
  fs.readFileSync(path.resolve(__dirname, "../../circuits/keygen/target/keygen.json"), "utf8")
);

const [privLo, privHi] = process.argv.slice(2);
if (!privLo || !privHi) {
  console.error("Usage: tsx zk-scripts/generatePubKey.ts <priv_lo> <priv_hi>");
  process.exit(1);
}

const noir = new Noir(circuit);
const { returnValue } = await noir.execute({ priv_lo: privLo, priv_hi: privHi });
const out = returnValue as unknown as [unknown, unknown];

const pubX = String(out[0]);
const pubY = String(out[1]);

const publicInputs = [
  ethers.zeroPadValue(ethers.toBeHex(BigInt(pubX)), 32),
  ethers.zeroPadValue(ethers.toBeHex(BigInt(pubY)), 32),
];

const encoded = ethers.AbiCoder.defaultAbiCoder().encode(["bytes", "bytes32[]"], ["0x", publicInputs]);
process.stdout.write(encoded);
process.exit(0);
