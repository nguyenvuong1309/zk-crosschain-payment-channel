# channel-state-halo2 — Halo2 migration reference (Milestone 4)

Trả lời câu hỏi "migrate Circom/Groth16 → Halo2/Plonky2 là sao" bằng code
thật thay vì lý thuyết. Đây là **1 circuit tham chiếu** dùng Halo2 (PSE fork,
KZG trên BN254) chứng minh cùng loại phát biểu như `channel_state.circom`
— **không phải bản thay thế production 1:1**, xem "Phạm vi & giới hạn" bên
dưới để biết chính xác cái gì đã làm và cái gì chưa.

## Đã chứng minh được (chạy thật, không phải mô tả)

```bash
cd circuits-halo2
cargo test --release --lib      # 12/12 test pass — MockProver, cross-check circomlibjs
cargo run --release --bin prove_and_export   # proof KZG THẬT: sinh + verify
```

Kết quả `prove_and_export` thật đã chạy: **proof 1152 byte, verify 2.4ms**,
`k=19` (2^19 hàng — tăng từ k=17 khi mở rộng STEPS 1→4, xem mục "Steps 1→4"
bên dưới), keygen ~5.6s, proving ~9.8s trên máy dùng để làm demo này.

### Circuit chứng minh gì

"tồn tại **4 update off-chain nối tiếp** (`STEPS=4`, khớp `steps=4` gốc của
`channel_state.circom` trước nâng cấp privacy), mỗi update partyA và partyB
đều ký EdDSA-Poseidon hợp lệ lên message
`M = Poseidon7(contractAddress, chainId, channelId, nonce, balanceA, balanceB)`,
nonce tăng chặt (range-check 64-bit, không chỉ so sánh trần), và
`balanceA + balanceB == totalDeposit` không đổi qua mọi bước" — dùng **đúng
phương trình EdDSAPoseidonVerifier của circomlib** (`S·B8 == R8 + c·(8·A)`,
xem `node_modules/circomlib/circuits/eddsaposeidon.circom`), **đúng hằng số
Poseidon BN254** trích trực tiếp từ `circomlibjs`, và **cùng domain
separator** (`contractAddress`/`chainId`) như `channel_state.circom` —
không tự nghĩ ra hằng số hay công thức mới ở bất kỳ đâu.

### Steps 1→4 + range check (đã đóng, cập nhật sau)

Bản đầu chỉ chứng minh 1 bước, không range-check balance/nonce — 2 gap tự
ghi trong bảng dưới. Đã đóng cả 2 mà **không cần gate/kỹ thuật mới**, đúng
như tự nhận định ban đầu ("lặp lại cơ học cùng gate"):
- `ChannelStateCircuit` giờ nhận `nonce/balanceA/balanceB/sigA/sigB` là
  mảng `[T; STEPS]` (`STEPS=4`), lặp qua từng bước với đúng các gate đã có
  (message hash, verify EdDSA, conservation), cộng thêm public input
  `startNonce`/`outNonce`/`finalBalanceA`/`finalBalanceB` để ràng buộc điểm
  đầu/cuối của chuỗi — không dùng commitment scheme (Poseidon(3)) như nâng
  cấp privacy sau này của `channel_state.circom`, vẫn NGOÀI phạm vi ở đây.
- Mỗi `balanceA[i]`/`balanceB[i]`/`nonce[i]`/`startNonce` được range-check
  64-bit (tái dùng `babyjubjub_chip::to_bits` sẵn có). Nonce tăng chặt được
  chứng minh bằng range-check `(nonce[i] - prevNonce - 1)` xuống 64-bit —
  cùng lý luận an toàn với `LessThan(64)` của circom (đòi hỏi input đã biết
  < 2^64 trước khi so sánh, xem docs/threat-model.md #3), chỉ dựng từ gate
  có sẵn thay vì 1 comparator chuyên dụng.
- Test mới: `non_increasing_nonce_is_rejected`, `wrong_claimed_final_state_is_rejected`.
- `k` tăng 17→19 (số hàng ~4x do lặp 4 bước + range check thêm), verify
  KZG thật vẫn chạy (2.4ms, không đổi đáng kể — verify không phụ thuộc số
  bước như proving).

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
| Số bước off-chain update/proof | 4 (`steps=4`) | ✅ **Đã khớp** (vòng cập nhật sau) — `STEPS=4`, lặp cùng 1 bộ gate mỗi bước, xem "Steps 1→4 + range check" phía trên |
| Domain separator (`contractAddress`, `chainId`) | Có, bake vào message ký | ✅ **Đã thêm** (vòng cập nhật sau) — cùng công thức `Poseidon7(contractAddress, chainId, channelId, nonce, balanceA, balanceB)`, xác nhận bằng witness thật từ circomlibjs |
| Trusted setup | Groth16, cần phase 2 riêng circuit (đã vá M4: multi-party ceremony) | **KHÔNG cần trusted setup per-circuit** — đúng lợi ích chính của Halo2/PLONK. Nhưng `prove_and_export.rs` hiện dùng SRS tạo cục bộ (`ParamsKZG::setup` với random cục bộ) — KHÔNG an toàn cho giá trị thật, xem mục KZG SRS bên dưới cho lý do chưa convert sang ceremony thật |
| Solidity on-chain verifier | Có (`Groth16Verifier.sol`, auto-gen) | **Chưa có** — viết verifier Solidity cho KZG/Halo2 là 1 việc lớn riêng (khác hẳn Groth16Verifier, cần pairing check khác), chưa làm |
| Range-check overflow (RANGE_BITS=64) | Có | ✅ **Đã thêm** (vòng cập nhật sau) — balanceA/balanceB/nonce mỗi bước + startNonce đều range-check 64-bit, nonce tăng chặt chứng minh bằng range-check hiệu số, cùng lý luận an toàn với `LessThan(64)` của circom |
| Privacy-commitment + chaining (`startCommitment`/`endCommitment` Poseidon(3), ẩn balance) | Có (nâng cấp sau M5, xem README gốc) | **Chưa có** — public input vẫn là balance trần (`finalBalanceA`/`finalBalanceB`), không phải commitment; đây là 1 nâng cấp riêng, lớn hơn "lặp lại cơ học", chưa làm |
| Custom gate hiệu năng (chip tái sử dụng, lookup table cho Poseidon S-box) | N/A (circom tự tối ưu qua R1CS) | Dùng 1 gate PLONK chung (`chip.rs`) cho mọi phép toán — đơn giản, dễ audit, nhưng KHÔNG tối ưu số hàng như 1 implementation Poseidon chip chuyên dụng (VD `halo2_gadgets`) |

### Vì sao dừng ở đây

Các phần **cơ học** của "full parity" (steps=4, domain separator, range
check) đã đóng — đúng như dự đoán ban đầu, không cần gate/kỹ thuật mới, chỉ
lặp lại cái đã có. Còn lại — **Solidity verifier cho KZG/Halo2** và **KZG
ceremony thật** (xem mục ngay dưới) — là việc khác hẳn về bản chất (viết
verifier on-chain mới, hoặc reverse-engineer định dạng nhị phân của 1 trusted
setup, sai ở đây nguy hiểm hơn không làm), cộng thêm **nâng cấp
privacy-commitment** (balance ẩn qua Poseidon(3), chaining nhiều proof) mà
`channel_state.circom` production đã có nhưng đòi hỏi thiết kế lại đáng kể,
không phải mở rộng cơ học như steps 1→4. Cái đã làm chứng minh **kiến trúc
khả thi thật sự** (cùng field BN254 nên KHÔNG cần non-native field arithmetic
phức tạp như nếu chọn Plonky2/Goldilocks) và **rủi ro mật mã học lớn nhất đã
kiểm chứng** (Baby Jubjub EC + Poseidon port đúng, cross-check với
circomlibjs thật, giờ chạy đúng ở quy mô 4 bước như production).

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
