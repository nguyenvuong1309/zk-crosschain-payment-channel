// Ambient module declarations for third-party libs that ship no TypeScript
// types (or none usable in strict mode). Kept intentionally loose (`any`) —
// the goal of converting this codebase to TypeScript is catching mistakes
// in OUR code (call sites, field names, arg order), not re-typing these
// libraries' internals from scratch. Our own functions around them (see
// input_gen/*.ts) still have full, precise types.

declare module "circomlibjs" {
  export interface EddsaPoint extends Array<unknown> {
    0: unknown;
    1: unknown;
  }
  export interface EddsaSignature {
    S: bigint;
    R8: [unknown, unknown];
  }
  export interface Eddsa {
    F: PoseidonField;
    babyJub: {
      Base8: unknown;
      mulPointEscalar(base: unknown, scalar: bigint): [unknown, unknown];
    };
    prv2pub(privKey: Buffer): [unknown, unknown];
    signPoseidon(privKey: Buffer, msg: unknown): EddsaSignature;
  }
  export interface PoseidonField {
    toObject(x: unknown): { toString(): string };
  }
  export interface Poseidon {
    (inputs: unknown[]): unknown;
    F: PoseidonField;
  }
  export function buildEddsa(): Promise<Eddsa>;
  export function buildPoseidon(): Promise<Poseidon>;
}

declare module "ffjavascript" {
  export const Scalar: {
    fromRprLE(buff: Uint8Array, offset: number, length: number): unknown;
    shr(a: unknown, n: number): { toString(): string };
  };
}

declare module "blake-hash" {
  interface BlakeHash {
    update(data: Buffer): BlakeHash;
    digest(): Buffer;
  }
  function createBlakeHash(algorithm: string): BlakeHash;
  export = createBlakeHash;
}
