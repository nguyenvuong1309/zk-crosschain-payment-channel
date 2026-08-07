# Circuits — trusted setup provenance

Xem `PLAN.md` cho kiến trúc/roadmap và `docs/threat-model.md` cho giả định
tin cậy đầy đủ. File này ghi lại **provenance cụ thể** của trusted setup
đang dùng (Milestone 4 — vá giả định #4), để ai kiểm tra lại cũng verify
được, không cần tin lời kể.

## Phase 1 — Powers of Tau (universal, không phụ thuộc circuit)

Dùng **Hermez / Polygon zkEVM Perpetual Powers of Tau ceremony** công khai,
degree 17 (đủ cho cả 2 circuit, xem bên dưới) — ceremony thật với hàng nghìn
người đóng góp độc lập qua nhiều năm, không phải file tự tạo.

```
File:   powersOfTau28_hez_final_17.ptau
Nguồn:  https://storage.googleapis.com/zkevm/ptau/powersOfTau28_hez_final_17.ptau
SHA256: 6b662a324867139fb1a20a324d90b6ff61856dfb23f59326909f14b0e2483ae0
Kích thước: 151,078,040 bytes
```

File **không** commit vào git (quá lớn) — tải lại bằng lệnh trên rồi bỏ vào
`circuits/build/`. Xác minh toàn bộ chuỗi đóng góp (chậm — file có hàng
nghìn contribution, mất ~40 phút CPU trên máy dùng để làm demo này):

```bash
npx snarkjs powersoftau verify build/powersOfTau28_hez_final_17.ptau
```

**Đã verify thật** (không chỉ tin lời kể) — kết quả: `Powers of Tau Ok!`,
xác nhận toàn bộ chuỗi đóng góp công khai hợp lệ về mặt mật mã học.

**Trước đó** (Milestone 2, trước khi vá #4), phase 1 dùng file tự tạo cục bộ
(`pot17_final.ptau`, 1 người đóng góp — xem log `pot17_new.log`/
`pot17_contrib.log` còn giữ lại làm bằng chứng lịch sử). File đó **không an
toàn cho production**, đã bị thay bằng ceremony công khai ở trên. Không xoá
để giữ lại lịch sử — không dùng để build gì nữa.

## Phase 2 — riêng từng circuit

Chạy qua `scripts/run_phase2_ceremony.sh <circuitName> <ptauFile>
[numContributions]` — mặc định 3 contribution độc lập, mỗi contribution
dùng entropy CSPRNG riêng (`/dev/urandom`), chạy process riêng, không lưu
lại randomness sau khi xong. Script tự động verify toàn bộ chuỗi đóng góp
bằng `snarkjs zkey verify` trước khi coi là xong.

**Giới hạn cần nói rõ**: đây vẫn là 1 người vận hành chạy tuần tự 3
contribution, KHÔNG phải 3 người/máy độc lập thật — an toàn của phase 2 vẫn
phụ thuộc việc người vận hành thực sự huỷ randomness sau mỗi bước (đúng
những gì script làm, nhưng không có cách nào bên thứ 3 xác minh độc lập
"người vận hành có thực sự huỷ hay không", khác với ceremony công khai thật
ở phase 1 nơi hàng nghìn bên độc lập tham gia). Nếu cần mức đảm bảo tương
đương phase 1, cần tổ chức ceremony phase 2 công khai thật (nhiều người thật
tham gia tuần tự, mỗi người tự thực hiện `zkey contribute` trên máy của họ)
trước khi dùng cho giá trị thật — xem PLAN.md Milestone 4.

| Circuit | zkey cuối | # contribution | Verify |
|---|---|---|---|
| `channel_state.circom` | `build/channel_state_final_v2.zkey` | 3 | `ZKey Ok!` |
| `consensus_proof.circom` | `build/consensus_proof_final.zkey` | 3 | `ZKey Ok!` |

Verifier Solidity export lại từ các zkey này:
`contracts/src/Groth16Verifier.sol`, `contracts/src/Groth16VerifierConsensus.sol`.

## Build lại từ đầu

```bash
pnpm install
npx circom circuits/channel_state.circom --r1cs --wasm --sym -l node_modules -o build
npx circom circuits/consensus_proof.circom --r1cs --wasm --sym -l node_modules -o build

curl -o build/powersOfTau28_hez_final_17.ptau \
  https://storage.googleapis.com/zkevm/ptau/powersOfTau28_hez_final_17.ptau

bash scripts/run_phase2_ceremony.sh channel_state build/powersOfTau28_hez_final_17.ptau 3
bash scripts/run_phase2_ceremony.sh consensus_proof build/powersOfTau28_hez_final_17.ptau 3
# lưu ý: zkey của channel_state phải nằm ở build/channel_state_final_v2.zkey
# (không phải _final.zkey) — xem scripts/prove_and_export.sh

npx snarkjs zkey export solidityverifier build/channel_state_final_v2.zkey /tmp/v.sol
npx snarkjs zkey export solidityverifier build/consensus_proof_final.zkey /tmp/vc.sol
# đổi tên contract trong /tmp/vc.sol thành Groth16VerifierConsensus trước khi copy
```
