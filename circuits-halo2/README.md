# channel-state-halo2 — Halo2 migration reference (Milestone 4)

Trả lời câu hỏi "migrate Circom/Groth16 → Halo2/Plonky2 là sao" bằng code
thật thay vì lý thuyết. Đây là **1 circuit tham chiếu** dùng Halo2 (PSE fork,
KZG trên BN254) chứng minh cùng loại phát biểu như `channel_state.circom`
— **không phải bản thay thế production 1:1**, xem "Phạm vi & giới hạn" bên
dưới để biết chính xác cái gì đã làm và cái gì chưa.

## Đã chứng minh được (chạy thật, không phải mô tả)

```bash
cd circuits-halo2
cargo test --release --lib      # 10/10 test pass — MockProver, cross-check circomlibjs
cargo run --release --bin prove_and_export   # proof KZG THẬT: sinh + verify
```

Kết quả `prove_and_export` thật đã chạy: **proof 1152 byte, verify 2.3ms**,
`k=17` (2^17 hàng — vừa với `channel_state.circom`'s pot17 ptau nếu sau
này convert sang KZG SRS thật, xem mục KZG SRS bên dưới), keygen ~3s,
proving ~5.8s trên máy dùng để làm demo này.

### Circuit chứng minh gì

"partyA và partyB đều ký EdDSA-Poseidon hợp lệ lên message
`M = Poseidon7(contractAddress, chainId, channelId, nonce, balanceA, balanceB)`,
và `balanceA + balanceB == totalDeposit`" — dùng **đúng phương trình
EdDSAPoseidonVerifier của circomlib** (`S·B8 == R8 + c·(8·A)`, xem
`node_modules/circomlib/circuits/eddsaposeidon.circom`), **đúng hằng số
Poseidon BN254** trích trực tiếp từ `circomlibjs`, và **cùng domain
separator** (`contractAddress`/`chainId`) như `channel_state.circom` —
không tự nghĩ ra hằng số hay công thức mới ở bất kỳ đâu.

### Xác nhận bit-for-bit với circomlibjs thật (không chỉ "trông giống đúng")

- `poseidon_ref.rs`: Poseidon t=3, t=6, t=7 khớp CHÍNH XÁC output của
  `circomlibjs.buildPoseidon()` cho cùng input.
- `babyjubjub_ref.rs`: `eddsa_poseidon_verify` chấp nhận 1 chữ ký EdDSA THẬT
  do `circomlibjs.buildEddsa().signPoseidon()` tạo ra, và từ chối khi tamper
  chữ ký/message.
- `circuit_test.rs`: witness dùng ĐÚNG khoá demo
  (`circuits/input_gen/build_channel_state_input.js`'s DEFAULT_PRIV_KEY_A/B)
  và message hash khớp `circomlibjs` — rồi chạy qua MockProver + KZG proof
  thật, không phải chỉ so khớp giá trị off-circuit.

## Phạm vi & giới hạn — đọc trước khi coi đây là "đã migrate xong"

| | `channel_state.circom` (production) | `channel-state-halo2` (reference này) |
|---|---|---|
| Số bước off-chain update/proof | 4 (`steps=4`) | **1** — chain nhiều bước là lặp lại cơ học cùng 1 gate, không làm khác về kỹ thuật, nhưng KHÔNG được làm ở đây do giới hạn thời gian |
| Domain separator (`contractAddress`, `chainId`) | Có, bake vào message ký | ✅ **Đã thêm** (vòng cập nhật sau) — cùng công thức `Poseidon7(contractAddress, chainId, channelId, nonce, balanceA, balanceB)`, xác nhận bằng witness thật từ circomlibjs |
| Trusted setup | Groth16, cần phase 2 riêng circuit (đã vá M4: multi-party ceremony) | **KHÔNG cần trusted setup per-circuit** — đúng lợi ích chính của Halo2/PLONK. Nhưng `prove_and_export.rs` hiện dùng SRS tạo cục bộ (`ParamsKZG::setup` với random cục bộ) — KHÔNG an toàn cho giá trị thật, xem mục KZG SRS bên dưới cho lý do chưa convert sang ceremony thật |
| Solidity on-chain verifier | Có (`Groth16Verifier.sol`, auto-gen) | **Chưa có** — viết verifier Solidity cho KZG/Halo2 là 1 việc lớn riêng (khác hẳn Groth16Verifier, cần pairing check khác), chưa làm |
| Range-check overflow (BALANCE_BITS=64) | Có | **Chưa có** — circuit này không giới hạn range của balanceA/balanceB |
| Custom gate hiệu năng (chip tái sử dụng, lookup table cho Poseidon S-box) | N/A (circom tự tối ưu qua R1CS) | Dùng 1 gate PLONK chung (`chip.rs`) cho mọi phép toán — đơn giản, dễ audit, nhưng KHÔNG tối ưu số hàng như 1 implementation Poseidon chip chuyên dụng (VD `halo2_gadgets`) |

### Vì sao dừng ở đây

"Full parity" (steps=4, domain separator, range check, Solidity verifier,
KZG ceremony thật) là khối lượng công việc tương đương làm lại M2 từ đầu
bằng 1 framework hoàn toàn khác — không tương xứng effort còn lại của
phiên làm việc này. Cái đã làm chứng minh **kiến trúc khả thi thật sự**
(cùng field BN254 nên KHÔNG cần non-native field arithmetic phức tạp như
nếu chọn Plonky2/Goldilocks) và **rủi ro mật mã học lớn nhất đã kiểm chứng**
(Baby Jubjub EC + Poseidon port đúng, cross-check với circomlibjs thật).

## KZG SRS — đã thử convert ptau thật, quyết định dừng lại có chủ đích

`ParamsKZG` cần đúng cấu trúc "powers of tau in G1/G2" — về lý thuyết là
những gì `circuits/build/powersOfTau28_hez_final_17.ptau` (ceremony công
khai Hermez/Polygon zkEVM, đã verify ở M4, xem `circuits/README.md`) chứa,
và halo2 có sẵn `ParamsKZG::from_parts(k, g, g_lagrange, g2, s_g2)` để dựng
params trực tiếp từ điểm thô — không cần tự viết lại serialization.

**Đã thử**: export ptau sang JSON qua `snarkjs powersoftau export json`
(141MB cho pot17) để đọc điểm `tauG1`/`tauG2` mà không phải tự parse định
dạng nhị phân. Nhưng khi kiểm tra cấu trúc mảng thực tế, `tauG1` có
262143 phần tử (= 2×131072 − 1, khớp việc Groth16 QAP cần bậc tới 2n−2)
trong khi cách đọc thẳng "mỗi điểm là 1 cặp (x,y)" đòi hỏi số phần tử
CHẴN — không khớp, nghĩa là format thật có chi tiết mã hoá khác giả định
ban đầu (rất có thể liên quan cách iden3 lưu trữ hoặc 1 quy ước offset
riêng) mà không rõ ràng nếu không đọc kỹ source `snarkjs`/`ffjavascript`.

**Quyết định dừng ở đây, có chủ đích**: đây là thành phần **trusted setup**
— sai sót ở bước "hiểu định dạng nhị phân" có thể sinh ra 1 SRS **trông như
hợp lệ nhưng sai âm thầm** (VD lệch điểm, sai thứ tự, nhầm dạng Montgomery),
nguy hiểm hơn hẳn việc giữ nguyên SRS cục bộ đã dán nhãn rõ ràng
"KHÔNG an toàn cho giá trị thật" như hiện tại. Reverse-engineer đúng định
dạng ptau của iden3 (không có spec chính thức ngắn gọn, phải đọc source) là
việc làm được nhưng cần thời gian kiểm chứng kỹ hơn những gì còn lại của
phiên này — để lại như 1 TODO rõ ràng thay vì làm ẩu.

## Cấu trúc code

```
src/
  field.rs                  parse hex string -> Fr
  poseidon_constants_t{3,6,7}.rs   hằng số trích từ circomlibjs (script: scripts/extract_poseidon_constants.js)
  poseidon_ref.rs            Poseidon thuần Rust, off-circuit — cross-check circomlibjs
  babyjubjub_ref.rs          Baby Jubjub + EdDSA verify thuần Rust, off-circuit
  chip.rs                    ArithChip — 1 gate PLONK chuẩn (mul/add/const/assert)
  poseidon_chip.rs           Poseidon IN-CIRCUIT, mirror poseidon_ref.rs
  babyjubjub_chip.rs         Baby Jubjub IN-CIRCUIT, mirror babyjubjub_ref.rs
  circuit.rs                 ChannelStateCircuit — ghép lại, public inputs
  circuit_test.rs            MockProver test với witness EdDSA thật
  bin/prove_and_export.rs    sinh + verify proof KZG thật
```
