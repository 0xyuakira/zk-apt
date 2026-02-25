// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Poseidon2} from "poseidon2-evm/Poseidon2.sol";
import {Field} from "poseidon2-evm/Field.sol";

abstract contract IncrementalMerkleTree {
    error InvalidDepth();
    error MerkleTreeFull();
    uint32 public constant ROOT_HISTORY_SIZE = 30;

    // Domain-separated empty leaf: Fr(keccak256("yuakira"))
    uint256 public constant ZERO_LEAF = 18364542742846956303373580614229727336767827731373926140228050716427120109049;

    Poseidon2 internal immutable poseidon2;
    uint32 public immutable treeDepth;
    uint32 public nextLeafIndex;
    uint32 public currentRootIndex;

    uint256[32] public cachedSubTree;
    mapping(uint256 => uint256) public roots;

    constructor(uint32 _treeDepth, address _poseidon2) {
        if (_treeDepth == 0 || _treeDepth > 32) revert InvalidDepth();
        treeDepth = _treeDepth;
        poseidon2 = Poseidon2(_poseidon2);

        roots[0] = _zeroAt(_treeDepth - 1);
    }

    function _insertLeaf(uint256 leaf) internal returns (uint256) {
        uint256 _nextLeafIndex = nextLeafIndex;
        if (_nextLeafIndex == uint256(1) << treeDepth) revert MerkleTreeFull();

        uint256 currentHash = leaf;

        for (uint32 level = 0; level < treeDepth; level++) {
            uint256 left;
            uint256 right;

            if (_nextLeafIndex % 2 == 0) {
                left = currentHash;
                right = _zeroAt(level);
                cachedSubTree[level] = currentHash;
            } else {
                left = cachedSubTree[level];
                right = currentHash;
            }

            currentHash = Field.toUint256(poseidon2.hash_2(Field.toField(left), Field.toField(right)));
            _nextLeafIndex /= 2;
        }

        nextLeafIndex += 1;
        currentRootIndex = (currentRootIndex + 1) % ROOT_HISTORY_SIZE;
        roots[currentRootIndex] = currentHash;
        return currentHash;
    }

    function isKnownRoot(uint256 root) public view returns (bool) {
        if (root == 0) {
            return false;
        }

        uint32 _currentRootIndex = currentRootIndex;
        uint32 i = _currentRootIndex;
        do {
            if (roots[i] == root) {
                return true;
            }
            if (i == 0) {
                i = ROOT_HISTORY_SIZE;
            }
            i--;
        } while (i != _currentRootIndex);
        return false;
    }

    function _zeroAt(uint32 level) internal pure returns (uint256) {
        if (level == 0) return ZERO_LEAF;
        if (level == 1) return 265165880919581242006263742449469351772439414086394417175427227405380575868;
        if (level == 2) return 15260887949103113569962427268282206036535473766196584453313056019504956772517;
        if (level == 3) return 10376427733167481661743394572995781492757952936028845256022937326023073745460;
        if (level == 4) return 3853157870342307294330284130968901543377116838297090883000266671780567082570;
        if (level == 5) return 20961189479143119099146611661986836733471017692115514338272437813169864569063;
        if (level == 6) return 5839695262605301984788515331500120934963359494328549174040437545226671067211;
        if (level == 7) return 21734126933099149315498493985470299593590660911570018885484736810649280089666;
        if (level == 8) return 9459943152776879110538412127358191222158475108315580077660962415645152277048;
        if (level == 9) return 16637562306402669556267289178924540453658611731245142581047921568813760318121;
        if (level == 10) return 11977864842599276722579600196685494279864299341577774653479810507209370828205;
        if (level == 11) return 5581290989107059751358815504001446365959720075658020028863223715257469755777;
        if (level == 12) return 7391523877659345238639110204663798797279618987084647646974691030469635431256;
        if (level == 13) return 14456292551361953284661963670940074422993075129277746514445220675089746531516;
        if (level == 14) return 4483472355925962666924386555760980932428121999619748878157149387547951473381;
        if (level == 15) return 12246554480491157150627615168557259352296407541777640289097609031430251136593;
        if (level == 16) return 20895732166956163221833102377062241746288546083437760802502650618196839307657;
        if (level == 17) return 12826569919653663243906331578300717262461973985343028197476939784642024953602;
        if (level == 18) return 17426121164761886899142312712664744005977700693694364930033658981782292883825;
        if (level == 19) return 2375184596241427539319732724926159840661274525875223335706725648391948547043;
        if (level == 20) return 2524892385373436366048994904454536730987421775250175994812015664993665874208;
        if (level == 21) return 8546997792576147644344827494893629556359363892647125279639537513268845422931;
        if (level == 22) return 14252098011642031975833508524155578185912499419958745694984367656396119009380;
        if (level == 23) return 1282927981511551300121516753559855646587488510204884730730498497720132904964;
        if (level == 24) return 17963346015703447341732760052925667416885431552387709028735171631918500889862;
        if (level == 25) return 10542989066819753793723402335535378939915240475343082542648685632303168477605;
        if (level == 26) return 17227693702375142748544146990612990097702911030702078064728766889378848294539;
        if (level == 27) return 3079966433055844071431213057395010173412228620214119594088112244034534595314;
        if (level == 28) return 17068798118669360573952052870581817992711690844975217154279166569687869167692;
        if (level == 29) return 21659605189009291238505449897503669070435143102541162487569500560683857750626;
        if (level == 30) return 9170286671112669224054404739843186790562000269234045209546678342856847775706;
        if (level == 31) return 14685483940183959487094599983170547675377738057779026038644660331990950059236;
        revert InvalidDepth();
    }
}
