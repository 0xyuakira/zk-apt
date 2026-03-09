# zk-apt
### ZK Auditable Privacy Transfer Protocol

[English](./README.en.md)

一个基于零知识证明（ZK）的隐私转账与可审计协议。通过 Noir 电路约束交易有效性，并由智能合约完成链上验证与状态更新。

`zk-apt` 的目标不是只做匿名，而是把下面三件事一起做对：
- ZK 电路约束（可证明）
- 隐私转账语义（可用）
- 审计通道（可解密、可追踪）

---

## 项目背景
纯隐私方案在真实业务中常常不够：
- 用户需要隐私
- 监管/风控又需要可验证审计线索

`zk-apt` 的设计是“选择性披露”：
- 普通观察者看不到明文转账语义
- 指定审计方可通过审计通道解密得到链路信息

---

## 核心设计

### 1) 电路
- `deposit`：生成 note 的 commitment，并在电路中约束其计算正确性
- `transfer`：花费旧 note、生成新 note，并在电路内约束接收方/审计方密文
- `withdraw`：从隐私池提现到公开地址，并约束审计密文

### 2) 合约侧验证与状态更新
`AuditablePrivacyTransfer.sol` 负责：
- 验证 proof
- 维护 nullifier（防双花）
- 维护 merkle roots（历史 root）
- 维护 commitment 集合

### 3) 电路内绑定加密一致性
密文不是“链下随便传”，而是在电路内被约束：
- 临时公钥一致性
- ECDH 共享密钥一致性
- 密文 = 明文 + mask 的一致性

因此 proof 只有在密文符合协议规则时才会通过。

---

## 业务流程

### Deposit
1. 用户准备 `(secret, owner_pub)`
2. 计算 note 的 commitment（Poseidon2）
3. 生成 `deposit` proof
4. 合约验真后把 commitment 插入 merkle tree

### Transfer
1. 发送方证明旧 note 成员关系 + nullifier 正确性
2. 生成新 note（给 recipient）
3. 电路约束 recipient/audit 两路密文
4. 合约验真后：标记 nullifier 已花费，插入新 commitment

Transfer 的关键难点是"所有权转移"：新 commitment 不只是一条新记录，而是把可花费权绑定到接收方公钥。
后续花费该 note 时，nullifier 的正确构造需要接收方私钥对应的 witness。发送方即使知道旧 note 与本次交易参数，也无法伪造接收方私钥相关 witness，因此不能再次花费这张新 note。

### Withdraw
1. 持有者证明 note 成员关系与花费授权
2. 电路约束提现相关公开输入与审计密文
3. 合约验真后向 recipient 转出固定面额资产

---

## 快速开始

### 环境依赖（建议固定版本）
- Node.js: `v22.22.0`
- nargo: `1.0.0-beta.19`
- bb CLI: `4.0.0-nightly.20260120`
- Solidity: `0.8.27`
- Foundry (forge): `1.5.1-stable`

### 安装脚本依赖
```bash
cd contracts/zk-scripts
npm install
```

### 编译电路
```bash
cd ../../circuits/deposit && nargo compile
cd ../transfer && nargo compile
cd ../withdraw && nargo compile
cd ../keygen && nargo compile
cd ../ecdh_helper && nargo compile
```

### 运行测试（建议串行）
```bash
cd ../../contracts
forge test --jobs 1
```
---
