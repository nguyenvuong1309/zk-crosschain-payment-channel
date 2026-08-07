# Local chains (Milestone 3)

Hai chain local độc lập, mô phỏng "Chain A" và "Chain B" cho kịch bản
cross-chain. Dùng Anvil (đi kèm Foundry) — chỉ cần 2 cổng khác nhau, mỗi cái
là 1 EVM hoàn toàn tách biệt (khác genesis, khác block time), đúng tinh thần
"hai máy trạng thái không tin cậy lẫn nhau" mà PLAN.md mô tả.

## Chạy

```bash
./start_chain_a.sh   # cổng 8545, chain id 31337
./start_chain_b.sh   # cổng 8546, chain id 31338
```

Mỗi script chạy nền (`&`), ghi log ra `./logs/`, và in PID ra để dừng sau.

## Deploy

Sau khi cả 2 chain chạy:

```bash
cd contracts && forge build   # nếu chưa build
cd ../relayer && pnpm install  # nếu chưa cài (cài cả pnpm workspace)
pnpm run deploy                 # ghi ra relayer/deployment.json
```

Script (`relayer/src/deploy.ts`) deploy `PaymentChannel.sol` lên MỖI chain
riêng biệt (2 địa chỉ khác nhau), và thêm `LightClientVerifier.sol` +
`Groth16VerifierConsensus.sol` trên Chain B — luồng demo hiện tại chỉ relay
1 chiều (trạng thái channel trên Chain A được validator-attest và settle
trên Chain B), nên chỉ Chain B cần light client. Xem
`relayer/src/e2e_demo.ts` (`pnpm run e2e`) cho kịch bản đầy đủ: mở kênh, đưa
kênh sang state mới trên Chain A, relay bằng proof Groth16 thật, mở kênh
khớp trên Chain B, settle qua `closeWithRemoteAttestation`, rút tiền.

## Lưu ý quan trọng

Đây là 2 chain **hoàn toàn độc lập**, không có finality/consensus thật liên
kết chúng — đúng bản chất của bài toán cross-chain. Mọi thông tin "chain A
biết gì về chain B" đều phải đi qua relayer + ZK proof, không có shortcut
nào khác. Xem docs/threat-model.md mục 6-8 cho giả định tin cậy liên quan.
