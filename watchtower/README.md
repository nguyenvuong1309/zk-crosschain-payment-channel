# Watchtower — Milestone 4

Bên thứ 3 bảo vệ 1 party khỏi bị gian lận trong lúc offline — xem PLAN.md
Milestone 4 và `docs/threat-model.md` mục #2.

## Vấn đề giải quyết

`PaymentChannel.sol` cho `CHALLENGE_PERIOD` (mặc định 1 ngày) để bên bị hại
phát hiện và phản đối 1 lần `closeUnilateral()`/`closeWithProof()` dùng state
cũ. Nếu bên bị hại offline suốt cửa sổ đó, đối phương "thắng" bằng state có
lợi cho họ — dù họ đã ký 1 state mới hơn trước đó. Watchtower là dịch vụ chạy
hộ bước phản đối này.

## Cách hoạt động

1. **Checkpoint**: sau mỗi lần 2 bên ký xong 1 state off-chain mới, 1 hoặc cả
   2 bên gửi kèm `POST /checkpoint` cho watchtower — state + 2 chữ ký.
   Watchtower **tự verify** chữ ký khớp `partyA`/`partyB` thật của kênh
   (đọc on-chain qua `hashState()`) trước khi lưu — không tin mù bất kỳ dữ
   liệu POST nào (`src/checkpoint.ts`).
2. **Theo dõi**: watchtower lắng nghe sự kiện `ChannelClosedUnilaterally` /
   `ChannelChallenged` trên `PaymentChannel` (`src/monitor.ts`).
3. **Phản đối hộ**: nếu state on-chain sau sự kiện có nonce THẤP HƠN state đã
   checkpoint, và cửa sổ challenge còn mở, watchtower tự gọi `challenge()`
   với state đúng — không cần bên bị hại tỉnh táo hay online.

## Vì sao gọi `challenge()` được mà không cần private key của party

`challenge()`/`challengeWithProof()` trong `PaymentChannel.sol` **cố tình bỏ**
modifier `onlyParty` (Milestone 4) — authorization thật sự nằm ở 2 chữ ký
kèm theo (hoặc ZK proof), không phải `msg.sender`. Ai gửi tx không quan
trọng, miễn state có đủ 2 chữ ký hợp lệ. Đây là điều kiện tiên quyết để
watchtower hoạt động mà không cần giữ khoá riêng tư của bất kỳ ai — nếu
watchtower biến mất hoặc bị hack, rủi ro chỉ là **liveness** (không ai phản
đối hộ), không phải mất tiền (không thể tạo challenge giả).

## Chạy demo end-to-end (đã verify thật)

```bash
cd contracts && forge build
anvil --port 8545 --chain-id 31337 &     # hoặc chains/start_chain_a.sh

cd ../watchtower
pnpm run e2e
```

Kịch bản: mở kênh, 2 vòng update off-chain (nonce 1 và 2, cả 2 đều
checkpoint), **partyB "biến mất"**, partyA gian lận đóng kênh bằng state
nonce=1 (cũ, có lợi cho A hơn) — watchtower tự phát hiện và gửi `challenge()`
với state nonce=2 đúng, **không cần partyB làm gì**. Payout cuối cùng khớp
chính xác state nonce=2 (0.2/1.8 ETH), không phải state gian lận (0.7/1.3).

## Chạy service thật

```bash
WATCHTOWER_CONTRACT=<địa chỉ PaymentChannel> pnpm start
```

Biến môi trường: `WATCHTOWER_RPC_URL` (mặc định `http://127.0.0.1:8545`),
`WATCHTOWER_CONTRACT` (bắt buộc), `WATCHTOWER_PORT` (mặc định `8787`),
`WATCHTOWER_PRIVATE_KEY` (tài khoản gửi tx `challenge()`, chỉ cần có ETH trả
gas — không cần quyền đặc biệt gì), `WATCHTOWER_STORE_PATH`.

## Giới hạn đã biết (ghi rõ trong `docs/threat-model.md` #2)

- Watchtower chỉ bảo vệ khỏi **1 lần** close/challenge gian lận trong 1 cửa
  sổ — nếu đối phương liên tục re-challenge, watchtower cần tiếp tục theo
  dõi (đã handle: lắng nghe cả `ChannelChallenged`, không chỉ
  `ChannelClosedUnilaterally`).
- 1 watchtower là 1 điểm liveness duy nhất — production nên chạy nhiều
  watchtower độc lập (bất kỳ ai cũng gọi `challenge()` được, không giới hạn
  số lượng watchtower cùng theo dõi 1 kênh).
- Store hiện là file JSON local (demo) — không phải database phân tán.
- Watchtower không tự phát hiện nếu 1 bên gửi thiếu checkpoint (VD bỏ qua 1
  vòng update) — chỉ bảo vệ được các state đã thực sự được checkpoint.
