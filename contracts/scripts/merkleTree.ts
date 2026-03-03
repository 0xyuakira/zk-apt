import { Barretenberg, Fr } from "@aztec/bb.js";

let bbPromise: Promise<Barretenberg> | undefined;
async function getBB(): Promise<Barretenberg> {
  if (!bbPromise) bbPromise = Barretenberg.new();
  return bbPromise;
}

async function hashLeftRight(left: string, right: string): Promise<string> {
  const bb = await getBB();
  const frLeft = Fr.fromString(left);
  const frRight = Fr.fromString(right);
  const hash = await bb.poseidon2Hash([frLeft, frRight]);
  return hash.toString();
}

export class PoseidonTree {
  levels: number;
  hashLeftRight: (left: string, right: string) => Promise<string>;
  storage: Map<string, string>;
  zeros: string[];
  totalLeaves: number;

  constructor(levels: number, zeros: string[]) {
    if (zeros.length < levels + 1) {
      throw new Error("Not enough zero values provided for the given tree height.");
    }
    this.levels = levels;
    this.hashLeftRight = hashLeftRight;
    this.storage = new Map();
    this.zeros = zeros;
    this.totalLeaves = 0;
  }

  async init(defaultLeaves: string[] = []): Promise<void> {
    if (defaultLeaves.length > 0) {
      this.totalLeaves = defaultLeaves.length;

      defaultLeaves.forEach((leaf, index) => {
        this.storage.set(PoseidonTree.indexToKey(0, index), leaf);
      });

      for (let level = 1; level <= this.levels; level++) {
        const numNodes = Math.ceil(this.totalLeaves / 2 ** level);
        for (let i = 0; i < numNodes; i++) {
          const left = this.storage.get(PoseidonTree.indexToKey(level - 1, 2 * i)) || this.zeros[level - 1];
          const right = this.storage.get(PoseidonTree.indexToKey(level - 1, 2 * i + 1)) || this.zeros[level - 1];
          const node = await this.hashLeftRight(left, right);
          this.storage.set(PoseidonTree.indexToKey(level, i), node);
        }
      }
    }
  }

  static indexToKey(level: number, index: number): string {
    return `${level}-${index}`;
  }

  getIndex(leaf: string): number {
    for (const [key, value] of this.storage.entries()) {
      if (value === leaf && key.startsWith("0-")) {
        return parseInt(key.split("-")[1], 10);
      }
    }
    return -1;
  }

  root(): string {
    return this.storage.get(PoseidonTree.indexToKey(this.levels, 0)) || this.zeros[this.levels];
  }

  proof(index: number): { root: string; pathElements: string[]; pathIndices: number[]; leaf: string } {
    const leaf = this.storage.get(PoseidonTree.indexToKey(0, index));
    if (!leaf) throw new Error("leaf not found");

    const pathElements: string[] = [];
    const pathIndices: number[] = [];

    this.traverse(index, (level, currentIndex, siblingIndex) => {
      const sibling = this.storage.get(PoseidonTree.indexToKey(level, siblingIndex)) || this.zeros[level];
      pathElements.push(sibling);
      pathIndices.push(currentIndex % 2);
    });

    return {
      root: this.root(),
      pathElements,
      pathIndices,
      leaf,
    };
  }

  async insert(leaf: string): Promise<void> {
    const index = this.totalLeaves;
    await this.update(index, leaf, true);
    this.totalLeaves++;
  }

  async update(index: number, newLeaf: string, isInsert = false): Promise<void> {
    if (!isInsert && index >= this.totalLeaves) {
      throw Error("Use insert method for new elements.");
    } else if (isInsert && index < this.totalLeaves) {
      throw Error("Use update method for existing elements.");
    }

    const keyValueToStore: Array<{ key: string; value: string }> = [];
    let currentElement = newLeaf;

    await this.traverseAsync(index, async (level, currentIndex, siblingIndex) => {
      const sibling = this.storage.get(PoseidonTree.indexToKey(level, siblingIndex)) || this.zeros[level];
      const [left, right] = currentIndex % 2 === 0 ? [currentElement, sibling] : [sibling, currentElement];
      keyValueToStore.push({ key: PoseidonTree.indexToKey(level, currentIndex), value: currentElement });
      currentElement = await this.hashLeftRight(left, right);
    });

    keyValueToStore.push({ key: PoseidonTree.indexToKey(this.levels, 0), value: currentElement });
    keyValueToStore.forEach(({ key, value }) => this.storage.set(key, value));
  }

  traverse(index: number, fn: (level: number, currentIndex: number, siblingIndex: number) => void): void {
    let currentIndex = index;
    for (let level = 0; level < this.levels; level++) {
      const siblingIndex = currentIndex % 2 === 0 ? currentIndex + 1 : currentIndex - 1;
      fn(level, currentIndex, siblingIndex);
      currentIndex = Math.floor(currentIndex / 2);
    }
  }

  async traverseAsync(
    index: number,
    fn: (level: number, currentIndex: number, siblingIndex: number) => Promise<void>
  ): Promise<void> {
    let currentIndex = index;
    for (let level = 0; level < this.levels; level++) {
      const siblingIndex = currentIndex % 2 === 0 ? currentIndex + 1 : currentIndex - 1;
      await fn(level, currentIndex, siblingIndex);
      currentIndex = Math.floor(currentIndex / 2);
    }
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

export async function merkleTree(leaves: string[]): Promise<PoseidonTree> {
  const TREE_HEIGHT = 20;
  const tree = new PoseidonTree(TREE_HEIGHT, ZERO_VALUES);

  await tree.init();

  for (const leaf of leaves) {
    await tree.insert(leaf);
  }

  return tree;
}
