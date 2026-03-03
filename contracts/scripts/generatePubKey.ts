import { ethers } from "ethers";
import { Noir } from "@noir-lang/noir_js";
import path from 'path';
import fs from 'fs';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const circuit = JSON.parse(fs.readFileSync(path.resolve(__dirname, '../../circuits/keygen/target/keygen.json'), 'utf8'));

export default async function generatePubKey() {
    const inputs = process.argv.slice(2);
    if (inputs.length < 2) {
        throw new Error("Usage: tsx scripts/generatePubKey.ts <priv_lo> <priv_hi>");
    }
    const lo = inputs[0];
    const hi = inputs[1];

    try {
        const noir = new Noir(circuit);
        const input = {
            priv_lo: lo,
            priv_hi: hi
        };
        const { returnValue } = await noir.execute(input);

        let pubX: string;
        let pubY: string;
        if (Array.isArray(returnValue) && returnValue.length >= 2) {
            pubX = String(returnValue[0]);
            pubY = String(returnValue[1]);
        } else if (returnValue && typeof returnValue === "object") {
            const rv = returnValue as Record<string, unknown>;
            pubX = String(rv.x);
            pubY = String(rv.y);
        } else {
            throw new Error(`Unexpected returnValue: ${JSON.stringify(returnValue)}`);
        }

        const publicInputs = [
            ethers.zeroPadValue(ethers.toBeHex(BigInt(pubX)), 32),
            ethers.zeroPadValue(ethers.toBeHex(BigInt(pubY)), 32),
        ];


        const result = ethers.AbiCoder.defaultAbiCoder().encode(["bytes", "bytes32[]"], ["0x", publicInputs]);
        return result;

    } catch (error) {
        console.log(error);
        throw error;
    }
}

(async () => {
    generatePubKey()
        .then((result) => {
            process.stdout.write(result);
            process.exit(0);
        })
        .catch((error) => {
            console.error(error);
            process.exit(1);
        });
})();
