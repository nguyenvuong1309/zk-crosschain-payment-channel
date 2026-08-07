# bls-validators — BLS12-381 validator committee (Milestone 4)

Thay `consensus_proof.circom` (5 validator demo ký EdDSA-Poseidon, verify
qua Groth16 proof) bằng **chữ ký BLS12-381 thật**, verify trực tiếp on-chain
qua precompile EIP-2537 (từ Prague/Pectra fork) — không cần ZK circuit cho
bước này nữa. Đây chính là cách light client Ethereum thật verify sync
committee attestation trên L1 (1 pairing check tổng hợp) — ZK light client
kiểu Succinct/Polyhedra tồn tại để NÉN việc này cho L2/cross-rollup, không
phải vì verify BLS on-chain là bất khả thi.

**Vẫn là committee giả lập** (xem `docs/threat-model.md` #6): 5 khoá demo
cố định (`keys.json`), KHÔNG phải sync committee thật của Ethereum. Cái thật
ở đây là **mật mã học** (khoá BLS12-381 thật, aggregate signature thật,
pairing check thật) — không phải danh tính/quy mô committee.

## Đã verify thật (không chỉ mô tả)

```bash
cd bls-validators && npm install
node generate_keys.js          # sinh 5 khoá demo (đã tự kiểm tra độ dài + scalar hợp lệ)
node sign.js 31337 1 12345 7   # ký aggregate cho validator 0,1,2 (bitmap=7)
```

```bash
cd ../contracts
forge test --match-contract "BLS12381Test|LightClientVerifierBLS"
```

- **`mapToCurve` của `@noble/curves` khớp bit-for-bit với precompile EIP-2537
  thật** (`0x11`, MAP_FP2_TO_G2) — test trên cả Anvil và `forge test` (revm),
  cùng input cho ra cùng output 256-byte, không sai 1 bit.
- 6/6 test `LightClientVerifierBLS.t.sol`: chấp nhận quorum thật (2 tập
  validator khác nhau), reject dưới ngưỡng, reject stateRoot bị tamper,
  reject stale blockNumber, reject khi bitmap khai báo nhiều validator hơn
  số thực sự ký.
- **Test tích hợp đầy đủ**: `LightClientVerifierBLS` là drop-in thay thế
  hoàn toàn cho `LightClientVerifier` cũ — cùng interface
  `ILightClientVerifier`, `PaymentChannel.closeWithRemoteAttestation()`
  chạy y hệt không đổi 1 dòng code, chỉ đổi contract light client được
  deploy (`LightClientVerifierBLSIntegration.t.sol`).

## Kiến trúc

- Pubkey validator: **G1** (128 byte, EIP-2537 encoding).
- Signature: **G2** (256 byte).
- Message → điểm G2: `_hashToG2(chainId, blockNumber, stateRoot)` trong
  `LightClientVerifierBLS.sol` — derive 2 phần tử Fp2 qua keccak256, map
  sang G2 qua precompile `0x11`. `sign.js` tính **CHÍNH XÁC cùng công thức**
  off-chain (dùng `@noble/curves`'s `G2.mapToCurve` — đã xác nhận khớp bit
  precompile) để ký.
- Aggregate: cộng điểm G1 (pubkey) và G2 (signature) của các validator
  tham gia qua precompile G1ADD (`0x0b`)/cộng điểm JS tương ứng.
- Verify: 1 pairing check qua precompile `0x0f`:
  `e(aggPubkey, M) · e(-G1, aggSig) == 1`.

## Giới hạn đã biết (đọc trước khi coi đây là "chuẩn Ethereum")

- **Không dùng RFC9380 `expand_message_xmd`/`hash_to_field` đầy đủ** — chỉ
  derive Fp2 trực tiếp từ keccak256, đơn giản hoá bước "hash-to-field".
  Vẫn dùng ĐÚNG precompile SWU-map chuẩn (`0x11`) cho bước "field→curve", chỉ
  đơn giản hoá bước "message→field". Không tương thích bit-for-bit với suite
  hash-to-curve chính thức của Ethereum consensus, nhưng an toàn tương
  đương (vẫn cần phá BLS12-381 để giả mạo).
- 5 khoá cố định, công khai trong repo — **tuyệt đối không dùng giữ tài sản
  thật**.
- Không có slashing (giống hạn chế đã ghi ở #8 trong threat-model).
- `keys.json`/`sign.js` không phải infra sản xuất — không có key rotation,
  không có HSM, chỉ dùng để demo.
