# ZK Cross-Chain Payment Channel

Nền tảng kỹ thuật cho một kênh thanh toán off-chain 2 bên, settle bằng
zero-knowledge proof, hướng tới khả năng settle xuyên chuỗi. Xem
**[PLAN.md](./PLAN.md)** cho kiến trúc đầy đủ, roadmap theo milestone, và
lựa chọn kỹ thuật đã chốt. Xem **[docs/threat-model.md](./docs/threat-model.md)**
cho giả định tin cậy và giới hạn của demo — đọc trước khi trình bày cho ai.

## Trạng thái

| Milestone | Mô tả | Trạng thái |
|---|---|---|
| M1 | Payment channel 1 chain (raw signature) | ✅ Xong — `contracts/` |
| M2 | ZK circuit + settle qua Groth16Verifier trên PaymentChannel, domain-separated (chống replay xuyên deployment) | ✅ Xong — `circuits/`, `contracts/src/Groth16Verifier.sol`. **Lưu ý**: ZK proof đắt hơn raw-signature close cho kênh 2 bên — xem PLAN.md M2 để hiểu giá trị thật của ZK ở đây không phải tiết kiệm gas. Test cần `forge test --ffi`. |
| M3 | Cross-chain qua ZK light client (thu nhỏ) | ✅ Xong — `circuits/circuits/consensus_proof.circom`, `contracts/src/LightClientVerifier.sol`, `relayer/`. Đã chạy end-to-end thật trên 2 Anvil (`relayer/src/e2e_demo.ts`). |
| M4 | Hoá cứng hướng production | 🔶 Phần lớn xong — xem bảng chi tiết bên dưới |

**M4 — chi tiết**:

| Hạng mục | Trạng thái |
|---|---|
| Multi-party trusted setup (Powers of Tau công khai + phase 2 3-contribution) | ✅ Xong — `circuits/README.md` |
| Watchtower — bên thứ 3 tự động challenge hộ party offline | ✅ Xong — `watchtower/` |
| Formal verification (Halmos, 4 property đã chứng minh) | ✅ 1 phần — `contracts/test/PaymentChannel.formal.t.sol` |
| Halo2 migration reference (chứng minh khả thi, chưa full parity) | ✅ Reference — `circuits-halo2/` |
| Audit circuit `channel_state.circom` (tìm + vá 1 lỗi thật: thiếu range-check nonce) | ✅ 1 vòng — `docs/threat-model.md` #3 |
| Security review `contracts/src/` | ✅ 1 vòng, không phát hiện lỗ hổng mới |
| BLS12-381 validator thật (khoá + aggregate signature + pairing check thật qua precompile EIP-2537) | ✅ Xong — `bls-validators/`, `contracts/src/LightClientVerifierBLS.sol` |
| Relayer watch-loop tự động (không cần gọi tay sau mỗi update) | ✅ Xong — `relayer/src/watch.ts`, `pnpm run watch` |
| Audit bảo mật độc lập bởi bên thứ 3 | ⏳ Cần nguồn lực ngoài, chưa làm |
| Sync committee Ethereum thật (SSZ, beacon header) | 🔶 Đang làm — xem Milestone 5, `PLAN.md` |

**Milestone 5 (6/6 việc kế hoạch gốc xong, còn 2 giới hạn hardening mở)** —
thay validator giả lập bằng sync committee Ethereum thật: verify off-chain
thành công cả chữ ký BLS aggregate **thật** lẫn SSZ merkle proof **thật**
của mainnet; `LightClientVerifierBLSGeneral.sol` verify quorum **342-of-512
thật**; `contracts/src/SSZ.sol` verify merkle proof on-chain (root khớp
chính xác off-chain) — gas thật đo được dùng để **quyết định xong on-chain
thay vì cần circuit riêng**; và đã **đăng ký + verify merkle proof của
đúng 512-key committee mainnet thật on-chain**
(`contracts/test/LightClientVerifierBLSReal.t.sol`, dữ liệu đóng băng từ
snapshot mainnet thật). Còn mở: chữ ký BLS thật chưa verify được on-chain
(cần RFC9380 hash-to-curve trên Solidity, việc lớn riêng) và chưa có
"trustless bootstrap" (vẫn tin 1 node public). Chi tiết đầy đủ: `PLAN.md`
Milestone 5.

55 test Foundry pass (`forge test`, cần `--ffi`), cộng thêm test hình thức
Halmos (`contracts/test/PaymentChannel.formal.t.sol`) và test Rust cho
circuit Halo2 (`circuits-halo2/`, `cargo test`).

## Cấu trúc

```
contracts/       Foundry — PaymentChannel.sol, BabyJubJub.sol, LightClientVerifier(BLS).sol + test
circuits/        Circom + snarkjs — channel_state.circom, consensus_proof.circom
circuits-halo2/  Rust/Halo2 — reference migration (chưa thay circuits/ hiện tại)
bls-validators/  BLS12-381 validator committee thật (Milestone 4)
watchtower/      Bên thứ 3 tự động bảo vệ party offline khỏi gian lận (Milestone 4)
relayer/         Node/ethers v6 — deploy 2 chain, relay proof Chain A -> Chain B, demo e2e
chains/          Script chạy 2 Anvil local (Chain A / Chain B)
docs/            Threat model, ghi chú thiết kế
```

## Chạy nhanh

```bash
# Clone kèm submodule (forge-std, openzeppelin-contracts trong contracts/lib/)
git clone --recurse-submodules <repo-url>
# Nếu đã clone thiếu submodule:
git submodule update --init --recursive

# relayer/, watchtower/, bls-validators/, circuits/ là 1 pnpm workspace
# (xem pnpm-workspace.yaml) — 1 lệnh cài hết cả 4 (tất cả code TypeScript,
# chạy trực tiếp qua tsx, không cần build step riêng). Cũng tự chạy `husky`
# (qua "prepare") — bật pre-commit hook chạy forge fmt --check + typecheck
# toàn workspace (~1-2s), KHÔNG chạy test nặng/e2e (những cái đó chỉ chạy
# trong CI, xem .github/workflows/ci.yml).
pnpm install

# Contracts
cd contracts && forge test -vv   # foundry.toml đã bật ffi=true, cần cho test proof ZK thật

# Circuit: compile, sinh input mẫu, tạo witness
cd circuits
pnpm run build:channel_state
pnpm run gen:input > build/input.json
node build/channel_state_js/generate_witness.js \
  build/channel_state_js/channel_state.wasm build/input.json build/witness.wtns
```

Trusted setup (Powers of Tau + phase 2) và proof/verify Groth16 đầy đủ: xem
lệnh trong lịch sử phiên làm việc hoặc `circuits/README.md` (đang bổ sung).

## Demo cross-chain (M3) đầy đủ

```bash
cd contracts && forge build
cd ../chains && ./start_chain_a.sh && ./start_chain_b.sh
cd ../relayer
pnpm run deploy   # deploy PaymentChannel + LightClientVerifier lên mọi chain trong chains.config.json
pnpm run e2e      # mở kênh, settle qua Chain A, relay proof thật, settle trên Chain B, rút tiền
```

`relayer/chains.config.json` liệt kê các chain theo tên (không giới hạn 2) —
thêm chain thứ 3/4 (hoặc trỏ `chainA`/`chainB` sang testnet thật) chỉ cần sửa
file này + `.env` (xem `relayer/.env.example`), không cần sửa code
`deploy.ts`/`index.ts`. `deploy.ts` tự deploy `LightClientVerifier` cho chain
nào có `"lightClient": true`. `npx tsx src/index.ts <channelId> [fromChain]
[toChain]` relay 1 lần theo yêu cầu giữa 2 tên chain bất kỳ trong
`deployment.json` (mặc định `chainA` → `chainB`).

**Watch-loop tự động (M4)**: `pnpm run watch [fromChain] [toChain]` chạy
daemon subscribe sự kiện đóng/challenge kênh trên chain nguồn và tự relay
ngay khi có state mới — không cần gọi `index.ts` tay sau mỗi update. Vá
giả định tin cậy #7 trong `docs/threat-model.md`.

Xem `chains/README.md` và `PLAN.md` Milestone 3 cho chi tiết luồng và giới
hạn đã biết (relay 1 chiều, channelId giả định trùng giữa 2 chain).

## Demo watchtower (M4)

```bash
cd contracts && forge build
anvil --port 8545 &
cd ../watchtower
pnpm run e2e   # partyB "biến mất", partyA gian lận đóng kênh, watchtower tự cứu
```

Xem `watchtower/README.md` cho chi tiết cơ chế và giới hạn.

## Demo BLS12-381 validator thật (M4)

```bash
cd bls-validators && pnpm run generate-keys
cd ../contracts && forge test --match-contract "BLS12381Test|LightClientVerifierBLS"
```

Xem `bls-validators/README.md` cho chi tiết mật mã học và giới hạn (committee
vẫn giả lập, không phải sync committee Ethereum thật).

## Halo2 migration reference (M4)

```bash
cd circuits-halo2
cargo test --release --lib          # MockProver + cross-check circomlibjs
cargo run --release --bin prove_and_export   # sinh + verify proof KZG thật
```

**Chưa thay thế** `circuits/circuits/channel_state.circom` — xem
`circuits-halo2/README.md` cho bảng so sánh phạm vi/giới hạn chi tiết.
