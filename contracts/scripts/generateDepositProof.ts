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
const bytecodePath = path.join(targetDir, "apt_deposit.json");
const witnessPath = path.join(targetDir, "apt_deposit.gz");
const proofPath = path.join(targetDir, "proof");
const publicInputsPath = path.join(targetDir, "public_inputs");

type Inputs = {
  commitment: string;
  secret: string;
  ownerPrivLo: string;
  ownerPrivHi: string;
  ownerPubX: string;
  ownerPubY: string;
};

function toBytes32Array(buf: Buffer): string[] {
  if (buf.length % 32 !== 0) {
    throw new Error(`public_inputs length ${buf.length} is not a multiple of 32`);
  }
  const out: string[] = [];
  for (let i = 0; i < buf.length; i += 32) {
    out.push("0x" + buf.subarray(i, i + 32).toString("hex"));
  }
  return out;
}

function parseArgs(argv: string[]): Inputs {
  if (argv.length !== 6) {
    throw new Error(
      "Usage: tsx scripts/generateDepositProof.ts <commitment> <secret> <ownerPrivLo> <ownerPrivHi> <ownerPubX> <ownerPubY>"
    );
  }
  const [commitment, secret, ownerPrivLo, ownerPrivHi, ownerPubX, ownerPubY] = argv;
  return { commitment, secret, ownerPrivLo, ownerPrivHi, ownerPubX, ownerPubY };
}

function runOrThrow(cmd: string, args: string[], cwd: string): void {
  try {
    execFileSync(cmd, args, { cwd, stdio: "pipe" });
  } catch (error) {
    const e = error as { stderr?: Buffer; message?: string };
    const stderr = e?.stderr ? e.stderr.toString("utf8") : "";
    const base = e?.message ?? String(error);
    throw new Error(`${base}${stderr ? `\n${stderr.trim()}` : ""}`);
  }
}

function writeProverToml(input: Inputs): void {
  const proverToml = [
    `commitment = "${input.commitment}"`,
    `secret = "${input.secret}"`,
    `ownerPrivLo = "${input.ownerPrivLo}"`,
    `ownerPrivHi = "${input.ownerPrivHi}"`,
    `ownerPubX = "${input.ownerPubX}"`,
    `ownerPubY = "${input.ownerPubY}"`,
    "",
  ].join("\n");
  fs.writeFileSync(proverTomlPath, proverToml, "utf8");
}

function generateProofArtifacts(): void {
  runOrThrow("nargo", ["execute"], depositDir);
  runOrThrow(
    "bb",
    ["prove", "-b", bytecodePath, "-w", witnessPath, "-o", targetDir, "--write_vk", "--verifier_target", "evm"],
    depositDir
  );
}

function encodeProofForSolidity(): string {
  const proofHex = "0x" + fs.readFileSync(proofPath).toString("hex");
  const publicInputs = toBytes32Array(fs.readFileSync(publicInputsPath));
  return AbiCoder.defaultAbiCoder().encode(["bytes", "bytes32[]"], [getBytes(proofHex), publicInputs]);
}

export default async function generateDepositProof(): Promise<string> {
  const input = parseArgs(process.argv.slice(2));
  writeProverToml(input);
  generateProofArtifacts();
  return encodeProofForSolidity();
}

(async () => {
  generateDepositProof()
    .then((result) => {
      process.stdout.write(result);
      process.exit(0);
    })
    .catch((error) => {
      console.error(error instanceof Error ? error.message : String(error));
      process.exit(1);
    });
})();
