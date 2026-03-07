import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";
import { execFileSync } from "child_process";
import { AbiCoder, getBytes } from "ethers";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const depositDir = path.resolve(__dirname, "../../circuits/deposit");
const targetDir = path.join(depositDir, "target");
const proverTomlPath = path.join(depositDir, "Prover.toml");

const [commitment, secret, ownerPrivLo, ownerPrivHi] = process.argv.slice(2);

if (!commitment || !secret || !ownerPrivLo || !ownerPrivHi) {
  console.error("Usage: tsx zk-scripts/generateDepositProof.ts <commitment> <secret> <ownerPrivLo> <ownerPrivHi>");
  process.exit(1);
}

const proverToml = [
  `commitment = "${commitment}"`,
  `secret = "${secret}"`,
  `owner_priv_lo = "${ownerPrivLo}"`,
  `owner_priv_hi = "${ownerPrivHi}"`,
  "",
].join("\n");

fs.writeFileSync(proverTomlPath, proverToml, "utf8");

execFileSync("nargo", ["execute"], { cwd: depositDir, stdio: "pipe" });
execFileSync(
  "bb",
  [
    "prove",
    "-b",
    path.join(targetDir, "apt_deposit.json"),
    "-w",
    path.join(targetDir, "apt_deposit.gz"),
    "-o",
    targetDir,
    "--write_vk",
    "--verifier_target",
    "evm",
  ],
  { cwd: depositDir, stdio: "pipe" }
);

const proof = "0x" + fs.readFileSync(path.join(targetDir, "proof")).toString("hex");
const rawPublicInputs = fs.readFileSync(path.join(targetDir, "public_inputs"));
const publicInputs: string[] = [];

for (let i = 0; i < rawPublicInputs.length; i += 32) {
  publicInputs.push("0x" + rawPublicInputs.subarray(i, i + 32).toString("hex"));
}

const encoded = AbiCoder.defaultAbiCoder().encode(["bytes", "bytes32[]"], [getBytes(proof), publicInputs]);
process.stdout.write(encoded);
