# Threat model & giả định tin cậy

> Tài liệu này liệt kê rõ những gì demo **không** bảo vệ được, để không ai
> (kể cả chính chúng ta sau vài tháng) nhầm demo này là production-ready.
> Xem PLAN.md để biết lộ trình khắc phục từng điểm.

## Lỗi đã tìm và sửa (code review ngày viết Milestone 2)

| # | Lỗi | Đã sửa? |
|---|---|---|
| A | `hashState()` (đường raw-signature) thiếu domain separator (`address(this)`, `block.chainid`) — chữ ký cho channel N trên deployment này replay được sang channel N trùng số trên deployment khác (VD Chain A ↔ Chain B) nếu 2 bên dùng chung địa chỉ ví | ✅ Đã sửa — thêm `address(this)` + `block.chainid` vào hash |
| B | `_payout()` gửi ETH cho cả 2 bên trong 1 tx, 1 bên revert là khoá tiền CẢ HAI vĩnh viễn (poison-pill DoS) | ✅ Đã sửa — chuyển sang pull-payment (`pendingWithdrawals` + `claim()`), gas stipend giới hạn 30k cho lần push đầu |
| C | Không có cách rút lại tiền nếu partyA mở kênh mà partyB không bao giờ `join()` | ✅ Đã sửa — thêm `cancelUnjoined()` |
| D | Đường **ZK proof** (`_verifyChannelProof`) có cùng lỗi domain separator như (A) | ✅ Đã sửa — `channel_state.circom` thêm `contractAddress`/`chainId` làm public input, đưa thẳng vào message được ký (Poseidon 6 input thay vì 4), circuit + Groth16Verifier build lại từ đầu (trusted setup v2). Contract check `pubSignals[10]==address(this)`, `pubSignals[11]==block.chainid`. Test `test_closeWithProof_revertsWhenProofBoundToADifferentDeployment` (FFI, dùng proof thật tạo cho địa chỉ khác) xác nhận bị từ chối đúng `DomainMismatch`. **Đánh đổi**: proof giờ không hardcode được nữa trong test (gắn chết với địa chỉ deploy) — test dùng `vm.ffi` gọi `circuits/scripts/prove_and_export.sh` tạo proof thật tại thời điểm chạy test (~6-8s/proof, cần `ffi = true` trong `foundry.toml`) |

## Giả định tin cậy hiện tại (Milestone 1–2)

| # | Giả định | Rủi ro nếu sai | Trạng thái |
|---|---|---|---|
| 1 | Mỗi party giữ khoá riêng an toàn (ECDSA on-chain + EdDSA off-chain) | Lộ khoá = mất toàn bộ tiền trong kênh | Ngoài phạm vi demo |
| 2 | `CHALLENGE_PERIOD` (1 ngày) đủ để bên bị hại (hoặc watchtower thay mặt) phát hiện & phản ứng | Bên bị hại offline lâu hơn 1 ngày VÀ không có watchtower nào theo dõi kênh → mất tiền vào state cũ | ✅ Đã có watchtower (Milestone 4, `watchtower/`) — xem `watchtower/README.md`. Watchtower là bên thứ 3 tự động gọi `challenge()` thay mặt party offline, dùng checkpoint (state + 2 chữ ký) đã tự verify trước đó. Cần đổi contract: bỏ `onlyParty` khỏi `challenge()`/`challengeWithProof()` (an toàn không đổi — vẫn cần 2 chữ ký hợp lệ/ZK proof, chỉ nới lỏng AI được gửi tx). **Giới hạn còn lại**: chỉ bảo vệ được state đã thực sự checkpoint (nếu party bỏ qua 1 vòng update không gửi checkpoint, watchtower không biết để bảo vệ); 1 watchtower là 1 điểm liveness (không phải safety) duy nhất — production nên chạy nhiều watchtower độc lập, cơ chế không giới hạn số lượng |
| 3 | Circuit `channel_state.circom` không có bug logic (under/overflow, thiếu constraint) | Proof giả có thể được chấp nhận | ⚠️ Đã audit 1 vòng (Milestone 4), tìm và vá 1 lỗi thật, nhưng chưa audit độc lập bởi bên thứ 3. **Lỗi tìm thấy & đã vá**: `nonce[i]` không được range-check (`Num2Bits`) trước khi đưa vào `LessThan(64)` để kiểm tra "nonce tăng dần" — trong khi `balanceA[i]`/`balanceB[i]` đã có. `LessThan` chỉ đúng (sound) khi cả 2 input đã nằm trong `[0, 2^64)`; nếu không, phép trừ mod field bên trong có thể wrap-around và khiến constraint "tăng dần" bị thoả mãn giả với 1 nonce field cực lớn không thực sự lớn hơn về số học thông thường — vi phạm đúng bất biến mà comment code khẳng định. Đã thêm `nonceRangeCheck[i] = Num2Bits(RANGE_BITS)` (giống hệt cách balance được range-check), rebuild circuit + ceremony phase 2 (3 contribution) + verifier Solidity, xác nhận bằng thực nghiệm: witness generation với nonce ≥ 2^64 giờ **reject đúng tại `nonceRangeCheck`** (trước đây sẽ không bị chặn ở bước này). 36/36 test Foundry vẫn pass sau khi đổi circuit + verifier. **Rủi ro thực tế của lỗi trước khi vá**: hạn chế — vẫn cần đủ 2 chữ ký hợp lệ cho message chứa nonce đó nên không thể giả mạo chữ ký, nhưng guarantee nội tại của circuit (độc lập với việc ký) không còn đúng như tài liệu mô tả — dạng lỗi kinh điển trong audit mạch ZK ("under-constrained input to a range-based comparator"). |
| 4 | Trusted setup Groth16 (Powers of Tau + phase 2) không bị 1 bên duy nhất kiểm soát toàn bộ | Người kiểm soát toàn bộ setup có thể tạo proof giả | ✅ Đã cải thiện đáng kể, còn 1 giới hạn nhỏ — xem `circuits/README.md` cho provenance đầy đủ. **Phase 1** (universal Powers of Tau): chuyển từ file tự tạo cục bộ sang **Hermez/Polygon zkEVM Perpetual Powers of Tau** công khai thật (`powersOfTau28_hez_final_17.ptau`, SHA256 `6b662a32...3ae0`, hàng nghìn người đóng góp độc lập qua nhiều năm) — verify toàn bộ chuỗi bằng `snarkjs powersoftau verify` (kết quả thật: `Powers of Tau Ok!`, ~40 phút CPU). **Phase 2** (riêng từng circuit — `channel_state.circom`, `consensus_proof.circom`): chạy 3 contribution độc lập qua `circuits/scripts/run_phase2_ceremony.sh`, mỗi contribution entropy CSPRNG riêng, verify toàn chuỗi bằng `snarkjs zkey verify` (kết quả `ZKey Ok!`). **Giới hạn còn lại**: phase 2 vẫn là 1 người vận hành chạy tuần tự 3 contribution (không phải nhiều người/máy độc lập thật) — an toàn phụ thuộc việc người vận hành thực sự huỷ randomness, không có bên thứ 3 nào xác minh độc lập được điều đó (khác phase 1, nơi hàng nghìn bên độc lập tự tham gia). Cần ceremony phase 2 công khai thật (nhiều người tự chạy `zkey contribute` trên máy riêng) trước khi dùng cho giá trị thật. |
| 5 | Đăng ký EdDSA public key khi mở kênh không bị giả mạo | Kẻ tấn công đăng ký khoá EdDSA thay người khác | ✅ Đã sửa — `open()`/`join()` giờ yêu cầu kèm chữ ký Schnorr (Baby Jubjub, thách thức Fiat-Shamir keccak256) chứng minh caller nắm giữ private key khớp public key đăng ký, verify bằng `contracts/src/BabyJubJub.sol` (point arithmetic thuần EVM + precompile modexp, không cần Poseidon on-chain). Domain-bound theo `(address(this), block.chainid, channelId, party)` — chữ ký cho channel này không replay được sang channel/deployment khác. `(0,0)` được miễn kiểm tra cho kênh chỉ dùng đường raw-signature (không cần danh tính EdDSA). Chữ ký sinh off-chain bởi `circuits/input_gen/eddsa_ownership.js`. Test: `contracts/test/KeyOwnership.t.sol` (6 test: accept hợp lệ, reject giả mạo/tamper/replay/not-on-curve, exemption 0,0). **Đánh đổi**: verify tốn ~3.45M gas/lần `open()`/`join()` có khoá thật — sau 2 vòng tối ưu (xem PLAN.md: affine → projective ~10.5M→3.8M, rồi 4-bit windowed scalar mult ~3.8M→3.45M), vẫn chấp nhận được cho demo nhưng đáng kể hơn phần còn lại của giao dịch; còn tối ưu được thêm (VD bảng precompute cho BASE8 cố định) nếu đưa lên production. |

## Giả định tin cậy bổ sung khi thêm Milestone 3 (cross-chain) — ĐÃ IMPLEMENT

M3 hiện đã chạy thật (circuit + verifier + relayer + demo end-to-end trên 2
Anvil, xem PLAN.md Milestone 3), không còn là scaffold — nhưng các giả định
tin cậy dưới đây vẫn giữ nguyên, vì chúng là giới hạn CHỦ ĐÍCH của demo, không
phải thứ "implement xong thì hết":

| # | Giả định | Rủi ro nếu sai |
|---|---|---|
| 6 | Tập "validator" là **giả lập** — 5 khoá demo cố định, ngưỡng 3/5. Có 2 implementation song song: (a) `consensus_proof.circom` — EdDSA-Poseidon ký từng validator, verify qua Groth16 proof, hardcode trong `LightClientVerifier.sol`; (b) **Milestone 4** — `bls-validators/` + `LightClientVerifierBLS.sol`, dùng **BLS12-381 thật** (khoá thật, aggregate signature thật, pairing check thật qua precompile EIP-2537), không qua ZK circuit. | Không phản ánh bảo mật thật ở CẢ 2 bản — bất kỳ ai có 3/5 khoá demo (công khai trong repo, `bls-validators/keys.json` hoặc `build_consensus_proof_input.js`) đều tạo được attestation giả cho BẤT KỲ giá trị nào. TUYỆT ĐỐI không dùng để giữ tài sản thật. Bản BLS **thật hơn về mật mã học** (BLS12-381 + pairing thật thay vì ZK proof của EdDSA) nhưng **committee vẫn giả lập y hệt** — không phải sync committee Ethereum thật, xem `bls-validators/README.md` cho giới hạn đầy đủ (VD: hash-to-curve đơn giản hoá, không đúng RFC9380 `expand_message_xmd` đầy đủ). |
| 7 | Relayer trung thực trong việc chuyển tiếp state/proof | Relayer ác ý có thể trì hoãn/từ chối chuyển tiếp (liveness), nhưng KHÔNG thể giả mạo proof hay attest sai giá trị (an toàn/safety vẫn giữ nhờ ZK + quorum check trong `LightClientVerifier.updateState`) — cần phân biệt rõ 2 loại rủi ro này khi trình bày demo. Relayer hiện tại (`relayer/src/index.js`) chạy 1 lần theo yêu cầu (`node src/index.js <channelId>`), CHƯA có watch-loop tự động theo dõi Chain A liên tục |
| 8 | Không có cơ chế slashing cho validator giả lập ký sai | Không áp dụng cho demo (không có gì để slash), nhưng PHẢI có trong bất kỳ bản thật nào dùng validator kinh tế |
| 9 | `stateRoot` trong `consensus_proof.circom` không verify block header/Merkle-Patricia-trie thật — là giá trị bất kỳ được yêu cầu attest (ở đây: hash trạng thái 1 channel cụ thể trên Chain A) | Validator "giả lập" có thể được yêu cầu ký BẤT KỲ giá trị nào, không chỉ trạng thái channel hợp lệ — an toàn của `closeWithRemoteAttestation` phụ thuộc hoàn toàn vào việc validator thật sự kiểm tra giá trị trước khi ký, điều circuit không tự đảm bảo được. Xem PLAN.md Milestone 4 cho hướng thay bằng consensus thật (BLS sync committee...) |
| 10 | Demo giả định `channelId` trùng nhau giữa channel nguồn (Chain A) và channel đích (Chain B) | Chỉ là đơn giản hoá cho demo (`relayer/src/e2e_demo.js`), không phải giới hạn kiến trúc — `closeWithRemoteAttestation` nhận `remoteContract`/`remoteChainId` tường minh nên không thực sự cần channelId trùng, chỉ là script demo chọn vậy cho dễ theo dõi |

## Formal verification (Milestone 4) — mới, tách khỏi bảng trên vì phạm vi khác #3 (circuit)

`PaymentChannel.sol` (Solidity, khác với #3 — circuit Circom) giờ có 4
property được **Halmos chứng minh hình thức** (`contracts/test/PaymentChannel.formal.t.sol`,
`FOUNDRY_PROFILE`/Halmos riêng, không chạy trong `forge test` thường):
`closeCooperative`/`closeUnilateral` không bao giờ thành công nếu vi phạm
bảo toàn giá trị; `withdraw()` không gọi thành công lần 2 sau CLOSED;
`challenge()` không bao giờ nhận nonce không tăng — chứng minh cho **mọi**
giá trị input có thể (bounded), không phải test 1 kịch bản cụ thể.

**Giới hạn đã phát hiện khi làm (đáng lưu ý cho ai audit tiếp)**: Halmos coi
`ecrecover` là hàm tự do (free function) — có thể "khớp" bất kỳ bytes chữ ký
nào với bất kỳ địa chỉ nào, không đòi hỏi có private key thật tương ứng. Property
nào dựa vào giả định "chữ ký không giả mạo được" sẽ gặp counterexample giả
(đã gặp, phải thiết kế lại). Vì vậy các property trên đều viết theo hướng
đúng bất kể mô hình hoá chữ ký — chỉ chứng minh các guard xảy ra TRƯỚC bước
verify chữ ký, hoặc hoàn toàn không phụ thuộc chữ ký. Đây là giới hạn của
**công cụ**, không phải lỗ hổng thật trong contract — nhưng có nghĩa Halmos
(ở cấu hình hiện tại) KHÔNG chứng minh được tính không-thể-giả-mạo của
ECDSA/chữ ký tự nó (bản thân ECDSA là an toàn mật mã học, chỉ là ngoài tầm
với của kiểu symbolic execution này). Certora (có license, mô hình hoá
crypto tốt hơn ở 1 số trường hợp) chưa làm.

## Halo2 migration reference (Milestone 4) — KHÔNG thay `channel_state.circom`

`circuits-halo2/` là 1 circuit THAM CHIẾU chứng minh việc migrate sang
Halo2/PLONK (không cần trusted setup per-circuit) khả thi — đã chạy thật
(MockProver + proof KZG thật, xem `circuits-halo2/README.md`). **Tuyệt đối
không dùng để thay `channel_state.circom` hiện tại** vì:

- **Thiếu domain separator** (contractAddress/chainId) — chính lỗ hổng đã
  vá ở "Lỗi đã tìm và sửa" #D phía trên. Dùng circuit này thay production
  mà không thêm domain separator sẽ TÁI TẠO LẠI lỗ hổng replay xuyên
  deployment đã vá.
- Chỉ chứng minh 1 bước off-chain update (steps=1), không phải 4.
- Chưa có Solidity verifier — không nối được vào `PaymentChannel.sol`.
- SRS (KZG) hiện tạo cục bộ, không an toàn cho giá trị thật (tương tự vấn đề
  trusted-setup-cá-nhân đã vá ở #4, nhưng chưa vá cho circuit Halo2 này).

## Điều KHÔNG được nói khi demo

- ❌ "Đây là bridge an toàn có thể chuyển tiền thật" — sai, Milestone 3 dùng validator giả lập.
- ❌ "ZK proof làm cho hệ thống này an toàn tuyệt đối" — ZK chỉ đảm bảo tính đúng đắn của phép tính được chứng minh (state transition hợp lệ), KHÔNG đảm bảo circuit đó mô tả đúng logic mong muốn (cần audit), KHÔNG đảm bảo liveness (relayer có thể không hoạt động), KHÔNG đảm bảo trusted setup sạch.
- ❌ "Không cần audit vì đã có test pass" — test chỉ chứng minh code chạy đúng với input đã nghĩ tới, không chứng minh không có input khai thác được.

## Điều CÓ THỂ nói đúng

- ✅ Kiến trúc đúng nguyên lý của các hệ thống ZK light client thật (zkBridge, Succinct) — chỉ thu nhỏ quy mô validator để demo chạy được trên máy cá nhân.
- ✅ Cơ chế dispute (challenge/withdraw) trong `PaymentChannel.sol` đã test và hoạt động đúng cho các kịch bản đối kháng cơ bản (bên gian lận dùng state cũ bị bên kia ghi đè).
- ✅ Circuit `channel_state.circom` compile được, sinh witness hợp lệ, và (sau khi test dưới đây hoàn tất) tạo/verify được proof Groth16 thật.
