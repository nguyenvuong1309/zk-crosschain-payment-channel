# ZK Cross-Chain Payment Channel — Kế hoạch chi tiết

> Nền tảng nghiên cứu/kỹ thuật cho một kênh thanh toán off-chain 2 bên, có thể
> settle xuyên chuỗi, dùng zero-knowledge proof để nén lịch sử update và (giai
> đoạn sau) để xác thực trạng thái của chuỗi khác mà không cần trust bên thứ ba.
> Đây là dự án nền tảng cho sản phẩm thật — mỗi mức đều được thiết kế để nâng
> cấp dần lên production, không phải bỏ đi làm lại.

## 0. Mục tiêu & phi mục tiêu

**Mục tiêu:**
- Có 1 kênh thanh toán off-chain chạy thật trên EVM local, đóng bằng ZK proof thay vì raw signature.
- Có 1 mô hình cross-chain thu nhỏ nhưng đúng kiến trúc (light client verify bằng ZK), chạy trên 2 chain local.
- Toàn bộ thiết kế có đường nâng cấp rõ ràng lên production (đổi tập validator giả lập → validator thật, đổi Circom → Halo2/Plonky2 nếu cần proving time tốt hơn).

**Phi mục tiêu (ở giai đoạn demo):**
- Không verify consensus thật của Ethereum/Solana (BLS aggregate signature thật, sync committee thật) — quá lớn cho 1 demo, để lại như TODO rõ ràng.
- Không tối ưu gas/proving time cho production.
- Không tự thiết kế crypto primitive mới — chỉ dùng pattern đã kiểm chứng (circomlib EdDSA, Groth16 qua snarkjs).
- Không phải audit-ready. Trước khi chạm tiền thật cần audit độc lập.

## 1. Kiến trúc tổng thể

```
                    ┌─────────────────────────┐
   off-chain        │   Relayer (Node/TS)      │
   updates          │   - theo dõi state       │
   (đã ký EdDSA)     │   - gọi prover           │
        │            │   - submit proof/tx      │
        ▼            └──────────┬───────────────┘
┌───────────────┐               │              ┌───────────────┐
│   Chain A      │◀──── ZK proof (light client)──▶│   Chain B      │
│ PaymentChannel │               │              │ PaymentChannel │
│ .sol           │               │              │ .sol           │
│ LightClient    │               │              │ LightClient    │
│ Verifier.sol   │               │              │ Verifier.sol   │
└───────────────┘               │              └───────────────┘
        ▲                       │                      ▲
        │              ┌────────┴────────┐             │
        └──────────────│  Circuits (Circom)│─────────────┘
                       │  - channel_state.circom (Mức 1) │
                       │  - consensus_proof.circom (Mức 3)│
                       └───────────────────────────────────┘
```

**3 lớp độc lập, xây tuần tự:**

| Lớp | Vấn đề giải quyết | Trạng thái |
|---|---|---|
| L1 — Payment channel 1 chain | Off-chain update, đóng kênh có/không tranh chấp | ✅ Xong (raw signature, chưa ZK) |
| L2 — ZK settlement | Nén chuỗi update off-chain thành 1 proof, không cần replay lịch sử khi settle | 🔧 Đang làm (circuit `channel_state.circom`) |
| L3 — Cross-chain ZK light client | Chứng minh trạng thái/consensus của chain A cho chain B mà không cần trust relayer | ⏳ Sau L2, dùng tập validator giả lập trước |

## 2. Lựa chọn kỹ thuật đã chốt

- **Chain**: 2× Anvil local (giả lập Chain A, Chain B), EVM.
- **Smart contract**: Solidity + Foundry.
- **ZK circuit**: Circom + snarkjs, chứng minh Groth16.
  - **Chữ ký trong circuit dùng EdDSA (Baby Jubjub, circomlib)**, KHÔNG dùng ECDSA/secp256k1 — vì verify ECDSA trong circuit cực tốn (hàng trăm nghìn constraint). Đây là pattern chuẩn của mọi ZK app (zkSync, Aztec, Tornado Cash...).
  - Hệ quả: danh tính "off-chain" của mỗi party trong kênh là 1 cặp khóa **EdDSA riêng**, tách biệt với địa chỉ ECDSA dùng để ký giao dịch on-chain. Khi mở kênh, mỗi party đăng ký public key EdDSA của mình on-chain (giống cách zkRollup có "L2 identity" tách khỏi "L1 address").
- **Hash trong circuit**: Poseidon (rẻ trong circuit, chuẩn ZK), không dùng keccak256 (đắt trong circuit — dù rẻ on-chain, ngược lại với EVM).
- **Trusted setup**: Powers of Tau công khai (Hermez ceremony) cho phase 1, circuit-specific setup (phase 2) cho từng circuit.

## 3. Roadmap chi tiết

### Milestone 1 — L1: Payment channel 1 chain (raw signature) — ✅ ĐÃ XONG
- [x] `PaymentChannel.sol`: open/join/closeCooperative/closeUnilateral/challenge/withdraw
- [x] Conservation check, challenge period 1 ngày
- [x] 7 test Foundry pass

### Milestone 2 — L2: ZK circuit cho chuỗi update hợp lệ
- [ ] **`channel_state.circom`**: chứng minh tồn tại chuỗi N update off-chain
      (mỗi update: nonce tăng dần, ký EdDSA hợp lệ bởi cả 2 bên, bảo toàn tổng
      số dư) dẫn từ state ban đầu (từ deposit on-chain) đến state cuối cùng.
      Output public: `channelId`, `finalNonce`, `finalBalanceA`, `finalBalanceB`.
- [ ] Script gen input (Node/TS): mô phỏng 2 bên trao đổi update, ký EdDSA bằng `circomlibjs`.
- [ ] Trusted setup (Powers of Tau + phase 2) cho circuit này.
- [ ] **`Groth16Verifier.sol`** (auto-generated bởi snarkjs).
- [ ] Sửa `PaymentChannel.sol`: thêm hàm `closeWithProof(proof, publicSignals)` —
      thay cho việc gửi raw `ChannelState + 2 signature`, giờ chỉ cần 1 proof.
      Giữ lại `closeCooperative`/`closeUnilateral` cũ để so sánh gas/UX.
- [ ] Test: so sánh gas cost giữa "raw signature close" và "ZK proof close" khi
      số lượng update off-chain lớn (VD 100 update) — đây là điểm chứng minh
      giá trị của ZK (proof cost const, replay cost tuyến tính).

### Milestone 3 — L3: Cross-chain qua ZK light client (thu nhỏ) — ✅ ĐÃ XONG
- [x] **`consensus_proof.circom`**: circuit toy — chứng minh ≥3 trong 5
      "validator" demo (khoá EdDSA giả lập, xem `docs/threat-model.md` #6)
      đã ký Poseidon(chainId, blockNumber, stateRoot). `stateRoot` cố ý mờ
      với circuit — không verify block header/Merkle-Patricia-trie thật
      (out of scope demo, xem Milestone 4). Trusted setup phase 2 tái dùng
      `pot17_final.ptau` sẵn có từ Milestone 2 (phase 1 không phụ thuộc
      circuit). Verifier: `contracts/src/Groth16VerifierConsensus.sol`.
- [x] **`LightClientVerifier.sol`** trên Chain B: nhận proof, verify quorum +
      committee (5 khoá demo hardcode), check `blockNumber` tăng dần (chặn
      replay/rewind), cập nhật `trustedStateRoot[chainId]`.
- [x] Relayer (`relayer/src/index.js`, Node/ethers v6): đọc state hiện tại
      của 1 channel trên Chain A, tính `remoteStateHash` (domain-separated,
      cùng công thức `closeWithRemoteAttestation`), gọi
      `circuits/scripts/prove_and_export_consensus.sh` sinh proof thật, submit
      `updateState()` lên Chain B.
- [x] Nối L2 + L3: `PaymentChannel.closeWithRemoteAttestation(channelId,
      remoteContract, remoteChainId, state)` — settle kênh trên Chain B theo
      đúng state đã được validator-attest cho CÙNG channelId trên Chain A,
      qua `lightClientVerifier.trustedStateRoot()`. Constructor thêm tham số
      `ILightClientVerifier` (immutable, `address(0)` = tắt tính năng này —
      mọi deployment/test cũ không đụng tới cross-chain đều dùng `address(0)`).
      Test: `contracts/test/LightClient.t.sol` (6 test, proof thật qua FFI).
- [x] Deploy script (`relayer/src/deploy.js`) + demo end-to-end thật
      (`relayer/src/e2e_demo.js`, `npm run e2e`): mở kênh trên Chain A, đưa
      kênh sang state mới bằng `closeUnilateral` (KHÔNG rút tiền trên Chain
      A), relay bằng proof Groth16 thật, mở kênh khớp trên Chain B, settle
      qua `closeWithRemoteAttestation`, rút tiền — đã CHẠY THẬT trên 2 Anvil
      thật (chainId 31337/31338), payout Chain B khớp chính xác state đã
      attest từ Chain A.
      **Giới hạn đã biết**: relay 1 chiều (A→B) only; demo giả định
      channelId trùng nhau giữa 2 chain (đơn giản hoá, không phải yêu cầu
      kiến trúc); relayer chạy 1 lần theo yêu cầu (`node src/index.js
      <channelId>`), chưa có watch-loop polling liên tục.

### Milestone 4 — Hoá cứng dần theo hướng production (không bắt buộc cho demo, ghi lại để không quên)
- [x] ~~Thay tập validator giả lập bằng verify thật (BLS aggregate
      signature)~~ — **Đã làm phần mật mã học, chưa phải sync committee
      Ethereum thật.** `bls-validators/` + `contracts/src/BLS12381.sol` +
      `contracts/src/LightClientVerifierBLS.sol`: 5 validator demo giờ dùng
      **chữ ký BLS12-381 thật** (khoá thật, aggregate signature thật qua
      cộng điểm G1/G2, pairing check thật), verify TRỰC TIẾP on-chain qua
      precompile EIP-2537 (Prague/Pectra) — bỏ hẳn Groth16 proof cho bước
      này (đúng cách light client Ethereum thật verify sync committee trên
      L1). **Đã verify thật**: `G2.mapToCurve` của `@noble/curves` khớp
      bit-for-bit precompile `0x11` thật (cả Anvil lẫn revm); 6/6 test
      `LightClientVerifierBLS.t.sol` (quorum thật, reject dưới ngưỡng/tamper
      stateRoot/stale block/giả mạo bitmap); **test tích hợp xác nhận drop-in
      thay thế hoàn toàn** cho `LightClientVerifier` cũ — cùng interface
      `ILightClientVerifier`, `closeWithRemoteAttestation()` không đổi 1
      dòng. 44/44 test Foundry pass. **Chưa làm**: sync committee Ethereum
      thật (SSZ merkleization, beacon header, RFC9380 hash-to-curve đầy đủ)
      — "phần khó nhất" ban đầu vẫn ngoài phạm vi. Chi tiết:
      `bls-validators/README.md`.
- [x] ~~Watchtower network~~ — **Đã xong.** `watchtower/` (Node/ethers v6):
      nhận checkpoint (state + 2 chữ ký, tự verify khớp partyA/partyB thật
      qua `hashState()` trước khi lưu — không tin mù dữ liệu POST), theo dõi
      sự kiện `ChannelClosedUnilaterally`/`ChannelChallenged`, tự động gọi
      `challenge()` với state đúng nếu phát hiện state on-chain cũ hơn.
      **Thay đổi contract cần thiết**: bỏ modifier `onlyParty` khỏi
      `challenge()`/`challengeWithProof()` — authorization chuyển hoàn toàn
      sang chữ ký/ZK proof kèm theo thay vì `msg.sender`, để bên thứ 3 gọi
      được mà không cần giữ private key của party nào (test:
      `test_challenge_acceptedFromThirdPartyNotAChannelParty`). Demo
      end-to-end thật (`npm run e2e` trong `watchtower/`) đã CHẠY THẬT trên
      Anvil: partyB "biến mất" hoàn toàn, partyA gian lận đóng kênh bằng
      state cũ, watchtower tự cứu — payout cuối khớp đúng state thật (không
      phải state gian lận). 36/36 test Foundry pass. Chi tiết:
      `watchtower/README.md`. Vá giả định tin cậy #2 trong
      `docs/threat-model.md`.
- [x] ~~Multi-party trusted setup ceremony~~ — **Đã cải thiện, còn 1 giới
      hạn nhỏ.** Phase 1: chuyển sang Hermez/Polygon zkEVM Perpetual Powers
      of Tau công khai thật (`powersOfTau28_hez_final_17.ptau`, SHA256
      `6b662a32...3ae0`, hàng nghìn người đóng góp thật). Phase 2
      (`channel_state.circom`, `consensus_proof.circom`): 3 contribution độc
      lập qua `circuits/scripts/run_phase2_ceremony.sh`, verify bằng
      `snarkjs zkey verify` (`ZKey Ok!`). Verifier Solidity build lại từ
      zkey mới, 35/35 test vẫn pass. **Còn lại**: phase 2 vẫn 1 người vận
      hành chạy tuần tự — cần ceremony phase 2 công khai thật (nhiều người
      độc lập) trước khi dùng cho giá trị thật. Chi tiết provenance đầy đủ:
      `circuits/README.md`. Vá giả định tin cậy #4 trong `docs/threat-model.md`.
- [x] ~~Đổi Circom/Groth16 → Halo2 hoặc Plonky2~~ — **Reference implementation
      đã chạy thật, chưa phải production migration.** `circuits-halo2/`
      (Rust, PSE halo2 fork, KZG trên BN254 — cùng field với Baby Jubjub nên
      không cần non-native field arithmetic như nếu chọn Plonky2/Goldilocks).
      Chứng minh: EdDSA-Poseidon verify (đúng phương trình
      `S·B8==R8+c·8A` của circomlib, đúng hằng số Poseidon BN254 trích từ
      circomlibjs) + conservation, cho 1 bước (steps=1, không phải 4).
      **Đã verify thật, không chỉ mô tả**: Poseidon t=3/6/7 khớp bit-for-bit
      circomlibjs; EdDSA verify chấp nhận chữ ký THẬT do circomlibjs tạo,
      reject khi tamper; MockProver pass cho witness thật + reject 2 trường
      hợp gian lận (chữ ký giả, vi phạm conservation); **sinh + verify 1
      proof KZG thật** (`cargo run --bin prove_and_export`: 1152 byte,
      verify 2.3ms). 10/10 test Rust pass.
      **Cập nhật thêm 1 vòng**: đã thêm domain separator
      (`contractAddress`/`chainId`, cùng công thức `channel_state.circom`)
      — đóng đúng lỗ hổng lỗi D nếu ai định dùng circuit này. `k` giảm
      17→còn 17 vừa đủ (không cần k=18), vẫn 10/10 test + proof KZG thật
      pass sau khi đổi. **Đã thử convert ptau Hermez → KZG SRS thật**
      (export JSON, đọc `tauG1`/`tauG2`) nhưng dừng có chủ đích khi phát
      hiện cấu trúc mảng không khớp giả định ban đầu (262143 phần tử
      `tauG1`, số lẻ, không chia đều thành cặp x/y) — sai sót ở bước hiểu
      định dạng nhị phân của 1 thành phần trusted-setup có thể sinh SRS
      sai âm thầm, rủi ro hơn giữ nguyên SRS cục bộ đã dán nhãn rõ "không an
      toàn". Chi tiết: `circuits-halo2/README.md`.
      **Vẫn chưa đạt full parity**: chỉ 1/4 bước, chưa có range-check
      overflow, chưa có Solidity verifier cho KZG, SRS vẫn cục bộ không an
      toàn. Không dùng để thay `channel_state.circom` hiện tại.
- [x] ~~Formal verification cho `PaymentChannel.sol`~~ — **Đã làm 1 phần
      (Halmos), Certora chưa làm.** `test/PaymentChannel.formal.t.sol`, 4
      property symbolic đã chứng minh (không phải test ví dụ cụ thể — Halmos
      duyệt MỌI giá trị input có thể, bounded):
      `closeCooperative`/`closeUnilateral` không bao giờ thành công nếu vi
      phạm bảo toàn giá trị (`balanceA+balanceB != deposits`); `withdraw()`
      không thể gọi thành công lần 2 sau khi CLOSED; `challenge()` không bao
      giờ chấp nhận nonce không tăng. **Giới hạn kỹ thuật quan trọng đã phát
      hiện khi làm**: Halmos coi `ecrecover` là hàm tự do (có thể "khớp" bất
      kỳ chữ ký nào với bất kỳ địa chỉ nào, không tính đến việc có private
      key thật hay không) — property ban đầu dựa vào "chữ ký không giả mạo
      được" cho counterexample giả, phải thiết kế lại property theo hướng
      luôn đúng bất kể mô hình hoá chữ ký (kiểm tra guard xảy ra TRƯỚC bước
      verify chữ ký trong code, hoặc guard hoàn toàn không phụ thuộc chữ ký).
      Cần Halmos ≥0.3.x + Python ≥3.10 (bản 0.1.13/Python 3.9 không hỗ trợ
      MCOPY/Cancun mà OpenZeppelin hiện dùng) — xem `contracts/README.md`.
      Certora (cần license/cloud service) chưa làm.
- [ ] Audit bảo mật độc lập trước khi chạm tiền thật (bên thứ 3 thật, chưa
      thể tự làm — xem mục audit circuit ngay dưới cho 1 vòng review đã làm).
- [x] ~~Audit circuit `channel_state.circom`~~ — **1 vòng review đã làm,
      tìm và vá 1 lỗi thật** (chưa thay thế được audit độc lập bên thứ 3).
      **Lỗi**: `nonce[i]` thiếu range-check trước `LessThan(64)` — có thể
      wrap-around field, làm constraint "nonce tăng dần" thoả mãn giả với
      nonce cực lớn. **Đã vá**: thêm `Num2Bits(64)` cho nonce giống balance,
      rebuild circuit + ceremony phase 2 + verifier, xác nhận thực nghiệm
      nonce ≥ 2^64 giờ bị reject đúng chỗ. 36/36 test vẫn pass. Chi tiết:
      `docs/threat-model.md` #3.
- [x] ~~Đăng ký EdDSA public key khi mở kênh phải verify on-chain~~ — **Đã sửa.**
      `open()`/`join()` giờ yêu cầu chữ ký Schnorr (Baby Jubjub, thách thức
      keccak256) chứng minh quyền sở hữu khoá, verify bằng
      `contracts/src/BabyJubJub.sol` (point arithmetic + precompile modexp,
      không cần Poseidon on-chain). Domain-bound theo
      `(address(this), chainid, channelId, party)`. `(0,0)` miễn kiểm tra cho
      kênh chỉ dùng raw-signature. Ký off-chain bằng
      `circuits/input_gen/eddsa_ownership.js`. Test: `KeyOwnership.t.sol`
      (6 test). Vá giả định tin cậy #5 trong `docs/threat-model.md`.
- [x] ~~Tối ưu gas BabyJubJub~~ — **Đã sửa, 2 vòng.** Vòng 1: `pointAdd`/
      `mulScalar` chuyển từ toạ độ affine (2 lời gọi precompile modexp/phép
      toán điểm) sang toạ độ projective (add-2008-bbjlp/dbl-2008-bbjlp,
      không cần nghịch đảo trong vòng lặp, chỉ 1 modexp lúc convert về
      affine ở cuối) — `open()` với khoá thật: ~10.5M → ~3.8M gas (~64%).
      Vòng 2: `mulScalar` đổi từ double-and-add sang **4-bit windowed**
      (bảng {0..15}·P dựng trước bằng 15 phép cộng, mỗi cửa sổ 4-bit chỉ
      tốn đúng 1 phép cộng thay vì tối đa 1 phép cộng/bit) — số phép cộng
      điểm giảm từ tối đa 256 xuống cố định 79 (15+64); số phép doubling
      không đổi (vẫn phụ thuộc độ dài bit của scalar, windowing không giảm
      được phần này). `open()` với khoá thật: ~3.8M → ~3.45M gas (~9%
      thêm). 44/44 test vẫn pass sau cả 2 vòng.
- [x] ~~Sửa domain separator thiếu ở đường ZK proof~~ — **Đã sửa.**
      `channel_state.circom` thêm `contractAddress`/`chainId` vào message
      được ký + public signal, trusted setup làm lại (v2, 12 public signal
      thay vì 10), `PaymentChannel.sol` check `pubSignals[10]/[11]` khớp
      `address(this)`/`block.chainid`. Test FFI (`ChannelStateProof.t.sol`,
      dùng `circuits/scripts/prove_and_export.sh` qua `vm.ffi`, cần
      `ffi = true` trong `foundry.toml`) xác nhận proof tạo cho địa chỉ
      deployment khác bị từ chối (`DomainMismatch`). 23/23 test pass.
      **Lưu ý pipeline**: dùng `snarkjs.groth16.fullProve` (JS API) mất
      ~20 phút bất thường trong môi trường này (gần như treo, CPU time không
      tăng) — chuyển sang shell ra CLI (`generate_witness.js` + `snarkjs
      groth16 prove` riêng biệt) thì chỉ ~6-8 giây/proof. Chưa rõ nguyên
      nhân gốc của việc `fullProve` chậm, ghi lại đây phòng khi cần dùng
      lại JS API cho việc khác.

## 4. Cấu trúc thư mục

```
zk-crosschain-payment-channel/
├── PLAN.md                      # file này
├── contracts/                   # Foundry project
│   ├── src/
│   │   ├── PaymentChannel.sol   # ✅ L1, đang thêm closeWithProof cho L2
│   │   ├── Groth16Verifier.sol  # auto-gen từ snarkjs (Milestone 2)
│   │   └── LightClientVerifier.sol  # Milestone 3
│   └── test/
├── circuits/                    # Circom + snarkjs
│   ├── channel_state.circom     # Milestone 2
│   ├── consensus_proof.circom   # Milestone 3
│   ├── input_gen/                # script Node/TS tạo input.json + ký EdDSA
│   └── build/                    # r1cs, wasm, zkey (gitignore)
├── relayer/                     # Node/TS: theo dõi + tạo proof + submit
├── chains/                      # config Anvil cho Chain A & B
└── docs/
    └── threat-model.md          # rủi ro, giả định tin cậy, giới hạn demo
```

## 5. Rủi ro & giả định cần nêu rõ trong mọi bản demo

- Tập validator ở Milestone 3 là **giả lập**, không phản ánh bảo mật của
  consensus thật — không được gọi là "cross-chain bridge an toàn" khi demo.
- Danh tính EdDSA off-chain tách biệt với địa chỉ ECDSA on-chain — cần cơ chế
  đăng ký/liên kết 2 khoá rõ ràng, nếu không sẽ có lỗ hổng giả mạo danh tính.
- Trusted setup Groth16 per-circuit: nếu circuit đổi, phải chạy lại phase 2
  ceremony — cần quy trình cho việc này trước khi tính đến production.
- Chưa có cơ chế slashing/penalty cho validator giả lập gian lận ở Milestone 3.

## 6. Trạng thái hiện tại

**Milestone 1**: ✅ xong (`PaymentChannel.sol`, 7 test pass).

**Milestone 2**: circuit + proving pipeline xong, còn thiếu phần nối vào contract.
- [x] `circuits/circuits/channel_state.circom` viết xong, compile thành công
      (61,004 non-linear constraint, 4 bước update × 2 chữ ký EdDSA/bước).
- [x] Script sinh input mẫu (`input_gen/generate_channel_state_input.js`,
      dùng `circomlibjs` để ký EdDSA/Poseidon) — chạy OK, sinh witness hợp lệ.
- [x] Trusted setup Groth16 (Powers of Tau bậc **17**, không phải 16 như dự
      kiến ban đầu — circuit có 68,429 wire, vượt giới hạn bậc 16).
- [x] Tạo proof + verify Groth16 end-to-end — **`snarkjs groth16 verify` → OK**.
      Public signals đầu ra khớp đúng update cuối cùng trong input mẫu
      (nonce=6, balanceA=400000, balanceB=1600000).
- [x] `Groth16Verifier.sol` auto-gen từ snarkjs, build sạch cùng
      `PaymentChannel.sol` (Foundry).
- [x] Nối `Groth16Verifier` vào `PaymentChannel.sol` qua `closeWithProof` +
      `challengeWithProof` (parse & cross-check public signals: channelId,
      2 EdDSA public key đã đăng ký, deposit ban đầu → decode outNonce/out
      Balance). 13 test pass (7 raw-signature cũ + 6 test mới dùng **1 proof
      Groth16 thật** hardcode từ witness mẫu, verify on-chain thành công,
      cùng các trường hợp revert: sai channelId, sai public key, proof bị
      tamper).
- [x] So sánh gas cost — **kết quả khác dự đoán ban đầu, sửa lại ở đây**:
      `closeUnilateral` (raw signature) ≈ 114k gas;
      `closeWithProof` (Groth16 verify) ≈ 249k gas chỉ riêng `verifyProof`,
      ~305k gas tổng. **ZK proof đắt hơn, không rẻ hơn.** Giả định ban đầu
      trong tài liệu này ("nén lịch sử → tiết kiệm gas khi lịch sử dài") là
      **sai** cho kênh 2 bên: đóng bằng raw signature vốn dĩ đã O(1) — chỉ
      cần state mới nhất được cả 2 ký, không cần replay lịch sử, nên không
      có "lịch sử dài" nào để nén ở đây. Giá trị thật của ZK trong thiết kế
      này nằm ở chỗ khác:
        - Nền tảng cho Milestone 3 (cross-chain) — nơi không tồn tại khái
          niệm "đối tác ký ngay cho state mới nhất" xuyên chuỗi, phải chứng
          minh trạng thái qua proof.
        - Cho phép 1 bên buộc tiến triển kênh dựa trên 1 chuỗi update cũ mà
          không cần đối tác hợp tác ký state mới (đối tác từ chối ký).
        - Riêng tư off-chain history tốt hơn nếu mở rộng để không lộ balance
          trung gian (hiện tại `outBalanceA/B` vẫn là public signal, nên
          demo NÀY không có tính riêng tư — cần thiết kế thêm nếu muốn).
- [ ] Lưu ý kỹ thuật cho bước tiếp: circuit cố định `steps = 4` — kênh có
      nhiều hơn 4 update off-chain phải nộp nhiều proof nối tiếp
      (`initBalance` của proof sau = `outBalance` của proof trước), hoặc
      tăng `steps` và chấp nhận constraint/proving-time tăng tuyến tính.

**Milestone 3**: scaffold đã tạo (`relayer/`, `chains/`), chưa có logic —
đang chờ Milestone 2 xong trước khi bắt đầu circuit `consensus_proof.circom`.

**Code review `PaymentChannel.sol`** (sau khi Milestone 2 xong): 3 lỗi thật
tìm thấy và sửa, xem `docs/threat-model.md` mục "Lỗi đã tìm và sửa" cho chi
tiết đầy đủ + test chứng minh (`test/PaymentChannelSecurityFixes.t.sol`, 9
test). Tóm tắt:
- **Domain separator thiếu trong `hashState()`** → chữ ký replay được xuyên
  deployment (nghiêm trọng với kế hoạch multi-chain của dự án) — đã sửa.
- **Payout kiểu push-cả-2-bên-1-tx** → 1 bên revert khoá tiền cả 2 vĩnh viễn
  — đã sửa bằng pull-payment (`pendingWithdrawals` + `claim()`).
- **Không có đường thoát nếu partyB không join** → đã thêm `cancelUnjoined()`.
- Đường ZK proof (`_verifyChannelProof`) có cùng lỗi domain separator như
  trên nhưng **CHƯA sửa** — cần sửa circuit + làm lại trusted setup, việc
  lớn, chưa làm. Không dùng `closeWithProof`/`challengeWithProof` khi có
  nhiều hơn 1 deployment cho tới khi vá.

Tổng số test hiện tại: **22/22 pass** (7 + 6 + 9).
