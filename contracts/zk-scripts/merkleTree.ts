import { Barretenberg, Fr } from "@aztec/bb.js";

const MOD = BigInt("21888242871839275222246405745257275088548364400416034343698204186575808495617");

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

let bbP: Promise<Barretenberg> | undefined;
async function hash2(left: string, right: string) {
  if (!bbP) bbP = Barretenberg.new();
  const bb = await bbP;
  const h = await bb.poseidon2Hash([toFr(left), toFr(right)]);
  return h.toString();
}

export class PoseidonTree {
  levels: number;
  zeros: string[];
  storage: Map<string, string>;
  totalLeaves: number;

  constructor(levels: number, zeros: string[]) {
    this.levels = levels;
    this.zeros = zeros.map((z) => toField(z).toString());
    this.storage = new Map();
    this.totalLeaves = 0;
  }

  static key(level: number, index: number) {
    return `${level}-${index}`;
  }

  root() {
    return this.storage.get(PoseidonTree.key(this.levels, 0)) || this.zeros[this.levels];
  }

  getIndex(leaf: string) {
    const want = toField(leaf).toString();
    for (const [k, v] of this.storage.entries()) {
      if (k.startsWith("0-") && v === want) return parseInt(k.split("-")[1], 10);
    }
    return -1;
  }

  proof(index: number) {
    const leaf = this.storage.get(PoseidonTree.key(0, index));
    if (!leaf) throw new Error("leaf not found");

    const pathElements: string[] = [];
    const pathIndices: number[] = [];

    let cur = index;
    for (let level = 0; level < this.levels; level++) {
      const sibling = cur % 2 === 0 ? cur + 1 : cur - 1;
      pathElements.push(this.storage.get(PoseidonTree.key(level, sibling)) || this.zeros[level]);
      pathIndices.push(cur % 2);
      cur = Math.floor(cur / 2);
    }

    return { root: this.root(), pathElements, pathIndices, leaf };
  }

  async insert(leaf: string) {
    let cur = toField(leaf).toString();
    let index = this.totalLeaves;

    for (let level = 0; level < this.levels; level++) {
      this.storage.set(PoseidonTree.key(level, index), cur);
      const sibling = this.storage.get(PoseidonTree.key(level, index ^ 1)) || this.zeros[level];
      cur = index % 2 === 0 ? await hash2(cur, sibling) : await hash2(sibling, cur);
      index = Math.floor(index / 2);
    }

    this.storage.set(PoseidonTree.key(this.levels, 0), cur);
    this.totalLeaves++;
  }
}

export const ZERO_VALUES: string[] = [
  "18364542742846956303373580614229727336767827731373926140228050716427120109049",
  "265165880919581242006263742449469351772439414086394417175427227405380575868",
  "15260887949103113569962427268282206036535473766196584453313056019504956772517",
  "10376427733167481661743394572995781492757952936028845256022937326023073745460",
  "3853157870342307294330284130968901543377116838297090883000266671780567082570",
  "20961189479143119099146611661986836733471017692115514338272437813169864569063",
  "5839695262605301984788515331500120934963359494328549174040437545226671067211",
  "21734126933099149315498493985470299593590660911570018885484736810649280089666",
  "9459943152776879110538412127358191222158475108315580077660962415645152277048",
  "16637562306402669556267289178924540453658611731245142581047921568813760318121",
  "11977864842599276722579600196685494279864299341577774653479810507209370828205",
  "5581290989107059751358815504001446365959720075658020028863223715257469755777",
  "7391523877659345238639110204663798797279618987084647646974691030469635431256",
  "14456292551361953284661963670940074422993075129277746514445220675089746531516",
  "4483472355925962666924386555760980932428121999619748878157149387547951473381",
  "12246554480491157150627615168557259352296407541777640289097609031430251136593",
  "20895732166956163221833102377062241746288546083437760802502650618196839307657",
  "12826569919653663243906331578300717262461973985343028197476939784642024953602",
  "17426121164761886899142312712664744005977700693694364930033658981782292883825",
  "2375184596241427539319732724926159840661274525875223335706725648391948547043",
  "2524892385373436366048994904454536730987421775250175994812015664993665874208",
];

export async function merkleTree(leaves: string[]) {
  const tree = new PoseidonTree(20, ZERO_VALUES);
  for (const leaf of leaves) {
    await tree.insert(leaf);
  }
  return tree;
}
