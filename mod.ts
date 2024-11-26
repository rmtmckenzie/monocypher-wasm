import WASM_BIN from './monocypher_wasm.ts';

export type InputBuffer = Uint8Array | readonly number[];

interface WasmExports {
  memory: WebAssembly.Memory;
  malloc(...args: number[]): number;
  free(...args: number[]): number;
  crypto_blake2b_ctx_size: number;
  crypto_poly1305_ctx_size: number;
  crypto_aead_ctx_size: number;
  crypto_verify16(...args: number[]): number;
  crypto_verify32(...args: number[]): number;
  crypto_verify64(...args: number[]): number;
  crypto_wipe(...args: number[]): number;
  crypto_aead_lock(...args: number[]): number;
  crypto_aead_unlock(...args: number[]): number;
  crypto_aead_init_x(...args: number[]): number;
  crypto_aead_init_djb(...args: number[]): number;
  crypto_aead_init_ietf(...args: number[]): number;
  crypto_aead_write(...args: number[]): number;
  crypto_aead_read(...args: number[]): number;
  crypto_argon2i(...args: number[]): number;
  crypto_argon2i_general(...args: number[]): number;
  crypto_blake2b(...args: number[]): number;
  crypto_blake2b_keyed(...args: number[]): number;
  crypto_blake2b_init(...args: number[]): number;
  crypto_blake2b_keyed_init(...args: number[]): number;
  crypto_blake2b_update(...args: number[]): number;
  crypto_blake2b_final(...args: number[]): number;
  crypto_argon2(...args: number[]): number;
  crypto_x25519_public_key(...args: number[]): number;
  crypto_x25519(...args: number[]): number;
  crypto_x25519_to_eddsa(...args: number[]): number;
  crypto_x25519_inverse(...args: number[]): number;
  crypto_x25519_dirty_small(...args: number[]): number;
  crypto_x25519_dirty_fast(...args: number[]): number;
  crypto_eddsa_key_pair(...args: number[]): number;
  crypto_eddsa_sign(...args: number[]): number;
  crypto_eddsa_check(...args: number[]): number;
  crypto_eddsa_to_x25519(...args: number[]): number;
  crypto_eddsa_trim_scalar(...args: number[]): number;
  crypto_eddsa_reduce(...args: number[]): number;
  crypto_eddsa_mul_add(...args: number[]): number;
  crypto_eddsa_scalarbase(...args: number[]): number;
  crypto_eddsa_check_equation(...args: number[]): number;
  crypto_chacha20_h(...args: number[]): number;
  crypto_chacha20_djb(...args: (number | bigint | null)[]): bigint;
  crypto_chacha20_ietf(...args: (number | null)[]): number;
  crypto_chacha20_x(...args: (number | bigint | null)[]): bigint;
  crypto_poly1305(...args: number[]): number;
  crypto_poly1305_init(...args: number[]): number;
  crypto_poly1305_update(...args: number[]): number;
  crypto_poly1305_final(...args: number[]): number;
  crypto_elligator_map(...args: number[]): number;
  crypto_elligator_rev(...args: number[]): number;
  crypto_elligator_key_pair(...args: number[]): number;
}

const instance = new WebAssembly.Instance(new WebAssembly.Module(WASM_BIN), {});
const wasm = instance.exports as unknown as WasmExports;

export const HASH_BYTES = 64;
export const KEY_BYTES = 32;
export const NONCE_BYTES = 24;
export const MAC_BYTES = 16;
export const CHACHA20_NONCE_BYTES = 8;
export const U64_BYTES = 8;

function readInt(position: number) {
  return new Uint32Array(wasm.memory.buffer, position)[0];
}

const blake2bCtxSize = readInt(wasm.crypto_blake2b_ctx_size);
const poly1305CtxSize = readInt(wasm.crypto_poly1305_ctx_size);
const aeadCtxSize = readInt(wasm.crypto_aead_ctx_size);

class AllocationContext {
  private allocPtrs: number[] = [];
  private wipeBuffers: Uint8Array[] = [];

  constructor() {}

  public alloc(size: number, { wipe = false }: { wipe?: boolean } = {}): Uint8Array {
    const allocPtr = wasm.malloc(size);
    this.allocPtrs.push(allocPtr);
    const buf = new Uint8Array(wasm.memory.buffer, allocPtr, size);
    if (wipe) {
      this.wipeBuffers.push(buf);
    }
    return buf;
  }

  public alloc32(size: number): Uint32Array {
    const allocPtr = wasm.malloc(size + size + size + size);
    this.allocPtrs.push(allocPtr);
    return new Uint32Array(wasm.memory.buffer, allocPtr, size);
  }

  public write(
    value: Uint8Array | readonly number[],
  ): number;
  public write(
    value: Uint8Array | readonly number[],
    {
      size,
      wipe,
      retBuffer,
    }: {
      size?: number;
      wipe?: boolean;
      retBuffer: true;
    },
  ): Uint8Array;
  public write(
    value: Uint8Array | readonly number[],
    {
      size,
      wipe,
    }: {
      size?: number;
      wipe?: boolean;
    },
  ): number;
  public write(
    value: Uint8Array | readonly number[],
    {
      size = value.length,
      wipe = false,
      retBuffer = false,
    }: {
      size?: number;
      wipe?: boolean;
      retBuffer?: boolean | undefined;
    } = {},
  ): number | Uint8Array {
    const buf = this.alloc(size);
    buf.set(value);
    if (wipe) {
      this.wipeBuffers.push(buf);
    }
    if (retBuffer) {
      return buf;
    } else {
      return buf.byteOffset;
    }
  }

  public write32(
    value: Uint32Array | readonly number[],
    {
      size = value.length,
      wipe = false,
    }: {
      size?: number;
      wipe?: boolean;
    } = {},
  ) {
    const buf = this.alloc32(size);
    buf.set(value);
    if (wipe) {
      this.wipeBuffers.push(new Uint8Array(buf, 0, buf.byteLength));
    }
    return buf.byteOffset;
  }

  free({ wipe = true }: { wipe: boolean } = { wipe: true }) {
    if (wipe) {
      for (const wipeBuffer of this.wipeBuffers) {
        wipeBuffer.fill(0);
      }
    }
    for (const allocPtr of this.allocPtrs) {
      wasm.free(allocPtr);
    }
  }
}

function allocCtx<T>(target: (ctx: AllocationContext) => T): T {
  const ctx = new AllocationContext();
  try {
    return target(ctx);
  } finally {
    ctx.free();
  }
}

function u8AllocCtx(
  target: (ctx: AllocationContext) => Uint8Array,
): Uint8Array {
  const ctx = new AllocationContext();
  try {
    return Uint8Array.from(target(ctx));
  } finally {
    ctx.free();
  }
}

export function verify(a: InputBuffer, b: InputBuffer): boolean {
  if (a.length == 16 && b.length == 16) {
    return allocCtx((ctx) => {
      const aOffset = ctx.write(a);
      const bOffset = ctx.write(b);
      return 0 == wasm.crypto_verify16(aOffset, bOffset);
    });
  } else if (a.length == 32 && b.length == 32) {
    return allocCtx((ctx) => {
      const aOffset = ctx.write(a);
      const bOffset = ctx.write(b);
      return 0 == wasm.crypto_verify32(aOffset, bOffset);
    });
  } else if (a.length == 64 && b.length == 64) {
    return allocCtx((ctx) => {
      const aOffset = ctx.write(a);
      const bOffset = ctx.write(b);
      return 0 == wasm.crypto_verify64(aOffset, bOffset);
    });
  } else {
    throw 'Must verify with two equal buffers of length 16, 32, or 64';
  }
}

export function wipe(input: Uint8Array) {
  input.fill(0);
}

export function aeadLock({
  key,
  nonce,
  ad,
  plainText,
}: {
  key: InputBuffer;
  nonce: InputBuffer;
  ad?: InputBuffer | undefined;
  plainText: InputBuffer;
}): { mac: Uint8Array; cipherText: Uint8Array } {
  return allocCtx((ctx) => {
    const keyOffset = ctx.write(key, { wipe: true });
    const nonceOffset = ctx.write(nonce);
    const adOffset = ad ? ctx.write(ad) : 0;
    const plainTextOffset = ctx.write(plainText);
    const mac = ctx.alloc(MAC_BYTES);
    const cipherText = ctx.alloc(plainText.length);
    wasm.crypto_aead_lock(
      cipherText.byteOffset,
      mac.byteOffset,
      keyOffset,
      nonceOffset,
      adOffset,
      ad?.length ?? 0,
      plainTextOffset,
      plainText.length,
    );
    return {
      mac: Uint8Array.from(mac),
      cipherText: Uint8Array.from(mac),
    };
  });
}

export function aeadUnlock({
  mac,
  key,
  nonce,
  ad,
  cipherText,
}: {
  mac: InputBuffer;
  key: InputBuffer;
  nonce: InputBuffer;
  ad?: InputBuffer | undefined;
  cipherText: InputBuffer;
}): InputBuffer | null {
  return allocCtx((ctx) => {
    const keyOffset = ctx.write(key, { wipe: true });
    const nonceOffset = ctx.write(nonce);
    const adOffset = ad ? ctx.write(ad) : 0;
    const cipherTextOffset = ctx.write(cipherText);
    const macOffset = ctx.write(mac);
    const plainText = ctx.alloc(cipherText.length);
    const result = wasm.crypto_aead_unlock(
      plainText.byteOffset,
      macOffset,
      keyOffset,
      nonceOffset,
      adOffset,
      ad?.length ?? 0,
      cipherTextOffset,
      cipherText.length,
    );

    if (result) {
      return null;
    }

    return Uint8Array.from(plainText);
  });
}

export class AeadContext {
  constructor(readonly data: Uint8Array) {}

  static from(data: Uint8Array) {
    return new AeadContext(Uint8Array.from(data));
  }

  get counter(): bigint {
    const as64 = new BigUint64Array(this.data.buffer, this.data.byteOffset, 1);
    return as64[0];
  }

  get key(): Uint8Array {
    return this.data.slice(U64_BYTES, U64_BYTES + KEY_BYTES);
  }

  get nonce(): Uint8Array {
    return this.data.slice(U64_BYTES + KEY_BYTES);
  }

  static length = aeadCtxSize;
}

export function aeadInit({ key, nonce, type = 'x' }: {
  key: InputBuffer;
  nonce: InputBuffer;
  type?: 'x' | 'djb' | 'ietf';
}): AeadContext {
  return allocCtx((ctx) => {
    const keyOffset = ctx.write(key);
    const nonceOffset = ctx.write(nonce);
    const context = ctx.alloc(AeadContext.length);
    switch (type) {
      case 'x': {
        wasm.crypto_aead_init_x(context.byteOffset, keyOffset, nonceOffset);
        break;
      }
      case 'djb': {
        wasm.crypto_aead_init_djb(context.byteOffset, keyOffset, nonceOffset);
        break;
      }
      case 'ietf': {
        wasm.crypto_aead_init_ietf(context.byteOffset, keyOffset, nonceOffset);
        break;
      }
    }
    return new AeadContext(Uint8Array.from(context));
  });
}

export function aeadWrite({
  context,
  ad,
  plainText,
}: {
  context: AeadContext;
  ad?: InputBuffer | undefined;
  plainText: InputBuffer;
}): {
  context: AeadContext;
  cipherText: Uint8Array;
  mac: Uint8Array;
} {
  return allocCtx((ctx) => {
    const adOffset = ad ? ctx.write(ad) : 0;
    const plainTextOffset = ctx.write(plainText, { wipe: true });
    const cipherText = ctx.alloc(plainText.length);
    const mac = ctx.alloc(MAC_BYTES);
    const contextBuffer = ctx.alloc(context.data.length, { wipe: true });
    contextBuffer.set(context.data);
    wasm.crypto_aead_write(
      contextBuffer.byteOffset,
      cipherText.byteOffset,
      mac.byteOffset,
      adOffset,
      ad?.length ?? 0,
      plainTextOffset,
      cipherText.length,
    );

    return {
      context: AeadContext.from(contextBuffer),
      cipherText: Uint8Array.from(cipherText),
      mac: Uint8Array.from(mac),
    };
  });
}

export function aeadRead({
  context,
  ad,
  cipherText,
  mac,
}: {
  context: AeadContext;
  ad?: InputBuffer | undefined;
  cipherText: InputBuffer;
  mac: InputBuffer;
}): {
  context: AeadContext;
  plainText: Uint8Array;
} | null {
  return allocCtx((ctx) => {
    const adOffset = ad ? ctx.write(ad) : 0;
    const cipherTextOffset = ctx.write(cipherText);
    const macOffset = ctx.write(mac);

    const plainText = ctx.alloc(cipherText.length, { wipe: true });
    const contextBuffer = ctx.alloc(context.data.length, { wipe: true });
    contextBuffer.set(context.data);
    const res = wasm.crypto_aead_read(
      contextBuffer.byteOffset,
      plainText.byteOffset,
      macOffset,
      adOffset,
      ad?.length ?? 0,
      cipherTextOffset,
      cipherText.length,
    );

    if (res) {
      return null;
    } else {
      return {
        context: AeadContext.from(contextBuffer),
        plainText: Uint8Array.from(plainText),
      };
    }
  });
}

export function blake2b({
  message,
  hashSize = HASH_BYTES,
  key,
}: {
  message: InputBuffer;
  hashSize?: number;
  key?: InputBuffer | undefined;
}): Uint8Array {
  return u8AllocCtx((ctx) => {
    let messageBytes: Uint8Array;
    if (hashSize < message.length) {
      messageBytes = ctx.alloc(message.length, { wipe: true });
    } else {
      messageBytes = ctx.alloc(hashSize);
    }

    if (key) {
      const keyOffset = ctx.write(key);
      wasm.crypto_blake2b_keyed(
        messageBytes.byteOffset,
        hashSize,
        keyOffset,
        key.length,
        messageBytes.byteOffset,
        messageBytes.length,
      );
    } else {
      wasm.crypto_blake2b(
        messageBytes.byteOffset,
        hashSize,
        messageBytes.byteOffset,
        message.length,
      );
    }

    return new Uint8Array(messageBytes.buffer, messageBytes.byteOffset, hashSize);
  });
}

export class Blake2b {
  private context: Uint8Array | null;
  constructor(public hashSize: number = HASH_BYTES, {
    key,
  }: {
    key?: InputBuffer | undefined;
  } = {}) {
    this.context = u8AllocCtx((ctx) => {
      const blake2bCtx = ctx.alloc(blake2bCtxSize);
      if (key) {
        const keyOffset = ctx.write(key, { wipe: true });
        wasm.crypto_blake2b_keyed_init(blake2bCtx.byteOffset, hashSize, keyOffset, key.length);
      } else {
        wasm.crypto_blake2b_init(blake2bCtx.byteOffset, this.hashSize);
      }
      return blake2bCtx;
    });
  }

  update(message: InputBuffer): void {
    if (!this.context) {
      throw "Can't call once finalized";
    }
    this.context = u8AllocCtx((ctx) => {
      const messageOffset = ctx.write(message, { wipe: true });
      const blake2bCtx = ctx.write(this.context!, { retBuffer: true });
      wasm.crypto_blake2b_update(blake2bCtx.byteOffset, messageOffset, message.length);
      return blake2bCtx;
    });
  }

  finalize(): Uint8Array {
    if (!this.context) {
      throw "Can't call once finalized";
    }
    const hash = u8AllocCtx((ctx) => {
      const blake2bCtx = ctx.write(this.context!);
      const hash = ctx.alloc(this.hashSize);
      wasm.crypto_blake2b_final(blake2bCtx, hash.byteOffset);
      return hash;
    });
    this.context = null;
    return hash;
  }
}

export function argon2({
  hashSize,
  algorithm,
  blocks,
  passes,
  lanes = 1,
  password,
  salt,
  key,
  ad,
}: {
  hashSize: 32 | 64;
  algorithm: 'i' | 'd' | 'id';
  blocks: number;
  passes: number;
  lanes?: number;
  password: InputBuffer;
  salt: InputBuffer;
  key?: InputBuffer | undefined;
  ad?: InputBuffer | undefined;
}): Uint8Array {
  return u8AllocCtx((ctx) => {
    let algorithmInt;
    switch (algorithm) {
      case 'd': {
        algorithmInt = 0;
        break;
      }
      case 'i': {
        algorithmInt = 1;
        break;
      }
      case 'id': {
        algorithmInt = 2;
        break;
      }
    }

    // write config
    const configOffset = ctx.write32([algorithmInt, blocks, passes, lanes]);

    // write inputs
    const inputOffset = ctx.write32([
      ctx.write(password),
      ctx.write(salt),
      password.length,
      salt.length,
    ]);

    // write extras
    let keyPointer = 0,
      adPointer = 0;
    if (key) {
      keyPointer = ctx.write(key);
    }
    if (ad) {
      adPointer = ctx.write(ad);
    }
    const extraOffset = ctx.write32([
      keyPointer,
      adPointer,
      key?.length ?? 0,
      ad?.length ?? 0,
    ]);

    const hash = ctx.alloc(hashSize);

    if (blocks < 8) {
      throw new Error('crypto_argon2: config.blocks must be at least 8');
    }
    const workArea = ctx.alloc(blocks * 1024);

    wasm.crypto_argon2(
      hash.byteOffset,
      hashSize,
      workArea.byteOffset,
      configOffset,
      inputOffset,
      extraOffset,
    );

    return hash;
  });
}

export function x25519PublicKey({ secretKey }: { secretKey: InputBuffer }) {
  return u8AllocCtx((ctx) => {
    const pubKey = ctx.alloc(KEY_BYTES);
    const secKeyOffset = ctx.write(secretKey, { wipe: true });

    wasm.crypto_x25519_public_key(pubKey.byteOffset, secKeyOffset);
    wasm.crypto_wipe(secKeyOffset, secretKey.length);

    return pubKey;
  });
}

export function x25519({
  yourSecretKey,
  theirPublicKey,
}: {
  yourSecretKey: InputBuffer;
  theirPublicKey: InputBuffer;
}) {
  return u8AllocCtx((ctx) => {
    const secKeyOffset = ctx.write(yourSecretKey);
    const pubKeyOffset = ctx.write(theirPublicKey);
    const sharedSecret = ctx.alloc(KEY_BYTES);
    wasm.crypto_x25519(sharedSecret.byteOffset, secKeyOffset, pubKeyOffset);
    wasm.crypto_wipe(secKeyOffset, yourSecretKey.length);
    return sharedSecret;
  });
}

export function x25519ToEddsa({ x25519 }: { x25519: InputBuffer }) {
  return u8AllocCtx((ctx) => {
    const x25519Offset = ctx.write(x25519);
    const eddsa = ctx.alloc(KEY_BYTES);
    wasm.crypto_x25519_to_eddsa(eddsa.byteOffset, x25519Offset);
    return eddsa;
  });
}

export function x25519Inverse({
  privateKey,
  curvePoint,
}: {
  privateKey: InputBuffer;
  curvePoint: InputBuffer;
}) {
  return u8AllocCtx((ctx) => {
    const privateKeyOffset = ctx.write(privateKey, { wipe: true });
    const curvePointOffset = ctx.write(curvePoint);
    const blindSalt = ctx.alloc(KEY_BYTES);
    wasm.crypto_x25519_inverse(
      blindSalt.byteOffset,
      privateKeyOffset,
      curvePointOffset,
    );
    return blindSalt;
  });
}

export function x25519Dirty(type: 'small' | 'fast', secretKey: InputBuffer) {
  return u8AllocCtx((ctx) => {
    const pk = ctx.alloc(KEY_BYTES);
    const secretKeyOffset = ctx.write(secretKey);
    switch (type) {
      case 'small': {
        wasm.crypto_x25519_dirty_small(pk.byteOffset, secretKeyOffset);
        break;
      }
      case 'fast': {
        wasm.crypto_x25519_dirty_fast(pk.byteOffset, secretKeyOffset);
      }
    }
    return pk;
  });
}

export function eddsaKeyPair(): {
  secretKey: Uint8Array;
  publicKey: Uint8Array;
  seed: Uint8Array;
} {
  return allocCtx((ctx) => {
    const secretKey = ctx.alloc(KEY_BYTES + KEY_BYTES);
    const publicKey = ctx.alloc(KEY_BYTES);
    const seed = ctx.alloc(KEY_BYTES);
    wasm.crypto_eddsa_key_pair(
      secretKey.byteOffset,
      publicKey.byteOffset,
      seed.byteOffset,
    );
    return {
      secretKey: Uint8Array.from(secretKey),
      publicKey: Uint8Array.from(publicKey),
      seed: Uint8Array.from(seed),
    };
  });
}

export function eddsaSign({
  secretKey,
  message,
}: {
  secretKey: InputBuffer;
  message: InputBuffer;
}): Uint8Array {
  return u8AllocCtx((ctx) => {
    const secretKeyOffset = ctx.write(secretKey);
    const messageOffset = ctx.write(message);
    const signature = ctx.alloc(KEY_BYTES + KEY_BYTES);
    wasm.crypto_eddsa_sign(
      signature.byteOffset,
      secretKeyOffset,
      messageOffset,
      message.length,
    );
    return signature;
  });
}

export function eddsaCheck({
  signature,
  publicKey,
  message,
}: {
  signature: InputBuffer;
  publicKey: InputBuffer;
  message: InputBuffer;
}): boolean {
  return allocCtx((ctx) => {
    const signatureOffset = ctx.write(signature);
    const publicKeyOffset = ctx.write(publicKey);
    const messageOffset = ctx.write(message);

    // if == 0, return true (i.e. true is equal)
    return !wasm.crypto_eddsa_check(
      signatureOffset,
      publicKeyOffset,
      messageOffset,
      message.length,
    );
  });
}

export function eddsaToX25519({ eddsa }: { eddsa: InputBuffer }) {
  return u8AllocCtx((ctx) => {
    const eddsaOffset = ctx.write(eddsa);
    const x25519 = ctx.alloc(KEY_BYTES);
    wasm.crypto_eddsa_to_x25519(x25519.byteOffset, eddsaOffset);
    return x25519;
  });
}

export function eddsaTrimScalar(input: InputBuffer) {
  return u8AllocCtx((ctx) => {
    const inputOffset = ctx.write(input);
    const out = ctx.alloc(KEY_BYTES);
    wasm.crypto_eddsa_trim_scalar(out.byteOffset, inputOffset);
    return out;
  });
}

export function eddsaReduce(expanded: InputBuffer) {
  return u8AllocCtx((ctx) => {
    const expandedOffset = ctx.write(expanded);
    const reduced = ctx.alloc(KEY_BYTES);
    wasm.crypto_eddsa_reduce(reduced.byteOffset, expandedOffset);
    return reduced;
  });
}

export function eddsaMulAdd({
  a,
  b,
  c,
}: {
  a: InputBuffer;
  b: InputBuffer;
  c: InputBuffer;
}) {
  return u8AllocCtx((ctx) => {
    const aOffset = ctx.write(a);
    const bOffset = ctx.write(b);
    const cOffset = ctx.write(c);
    const r = ctx.alloc(KEY_BYTES);
    wasm.crypto_eddsa_mul_add(r.byteOffset, aOffset, bOffset, cOffset);
    return r;
  });
}

export function eddsaScalarbase(scalar: InputBuffer) {
  return u8AllocCtx((ctx) => {
    const scalarOffset = ctx.write(scalar);
    const point = ctx.alloc(KEY_BYTES);
    wasm.crypto_eddsa_scalarbase(point.byteOffset, scalarOffset);
    return point;
  });
}

export function eddsaCheckEquation({
  signature,
  publicKey,
  hRam,
}: {
  signature: InputBuffer;
  publicKey: InputBuffer;
  hRam: InputBuffer;
}): boolean {
  return allocCtx((ctx) => {
    const signatureOffset = ctx.write(signature);
    const publicKeyOffset = ctx.write(publicKey);
    const hRamOffset = ctx.write(hRam);

    // if 0, equal, otherwise not equal
    // true is equal, false is not equal
    return !wasm.crypto_eddsa_check_equation(
      signatureOffset,
      publicKeyOffset,
      hRamOffset,
    );
  });
}

export function chacha20hash({
  key,
  nonce,
}: {
  key: InputBuffer;
  nonce: InputBuffer;
}) {
  return u8AllocCtx((ctx) => {
    const keyOffset = ctx.write(key);
    const nonceOffset = ctx.write(nonce);
    const out = ctx.alloc(KEY_BYTES);
    wasm.crypto_chacha20_h(out.byteOffset, keyOffset, nonceOffset);
    return out;
  });
}

export function chacha20djb({
  plainTextOrSize,
  key,
  nonce,
  ctr,
}: {
  plainTextOrSize: InputBuffer | number;
  key: InputBuffer;
  nonce: InputBuffer;
  ctr: bigint;
}): { cipherText: Uint8Array; ctr: bigint } {
  return allocCtx((ctx) => {
    if (typeof plainTextOrSize == 'number') {
      const keyOffset = ctx.write(key);
      const nonceOffset = ctx.write(nonce);
      const cipherText = ctx.alloc(plainTextOrSize);
      const ret = wasm.crypto_chacha20_djb(
        cipherText.byteOffset,
        null,
        plainTextOrSize,
        keyOffset,
        nonceOffset,
        ctr,
      );
      return {
        ctr: ret,
        cipherText: Uint8Array.from(cipherText),
      };
    } else {
      const plainText = plainTextOrSize;
      const plainTextOffset = ctx.write(plainText);
      const keyOffset = ctx.write(key);
      const nonceOffset = ctx.write(nonce);
      const cipherText = ctx.alloc(plainText.length);
      const ret = wasm.crypto_chacha20_djb(
        cipherText.byteOffset,
        plainTextOffset,
        plainText.length,
        keyOffset,
        nonceOffset,
        ctr,
      );
      return {
        ctr: ret,
        cipherText: Uint8Array.from(cipherText),
      };
    }
  });
}

export function chacha20ietf({
  plainTextOrSize,
  key,
  nonce,
  ctr,
}: {
  plainTextOrSize: InputBuffer | number;
  key: InputBuffer;
  nonce: InputBuffer;
  ctr: number;
}): { cipherText: Uint8Array; ctr: number } {
  return allocCtx((ctx) => {
    if (typeof plainTextOrSize == 'number') {
      const keyOffset = ctx.write(key);
      const nonceOffset = ctx.write(nonce);
      const cipherText = ctx.alloc(plainTextOrSize);
      const ret = wasm.crypto_chacha20_ietf(
        cipherText.byteOffset,
        null,
        plainTextOrSize,
        keyOffset,
        nonceOffset,
        ctr,
      );
      return {
        ctr: ret,
        cipherText: Uint8Array.from(cipherText),
      };
    } else {
      const plainText = plainTextOrSize;
      const plainTextOffset = ctx.write(plainText);
      const keyOffset = ctx.write(key);
      const nonceOffset = ctx.write(nonce);
      const cipherText = ctx.alloc(plainText.length);
      const ret = wasm.crypto_chacha20_ietf(
        cipherText.byteOffset,
        plainTextOffset,
        plainText.length,
        keyOffset,
        nonceOffset,
        ctr,
      );
      return {
        ctr: ret,
        cipherText: Uint8Array.from(cipherText),
      };
    }
  });
}

export function chacha20x({
  plainTextOrSize,
  key,
  nonce,
  ctr,
}: {
  plainTextOrSize: InputBuffer | number;
  key: InputBuffer;
  nonce: InputBuffer;
  ctr: bigint;
}): { cipherText: Uint8Array; ctr: bigint } {
  return allocCtx((ctx) => {
    if (typeof plainTextOrSize == 'number') {
      const keyOffset = ctx.write(key);
      const nonceOffset = ctx.write(nonce);
      const cipherText = ctx.alloc(plainTextOrSize);
      const ret = wasm.crypto_chacha20_x(
        cipherText.byteOffset,
        null,
        plainTextOrSize,
        keyOffset,
        nonceOffset,
        ctr,
      );
      return {
        ctr: ret,
        cipherText: Uint8Array.from(cipherText),
      };
    } else {
      const plainText = plainTextOrSize;
      const plainTextOffset = ctx.write(plainText);
      const keyOffset = ctx.write(key);
      const nonceOffset = ctx.write(nonce);
      const cipherText = ctx.alloc(plainText.length);
      const ret = wasm.crypto_chacha20_x(
        cipherText.byteOffset,
        plainTextOffset,
        plainText.length,
        keyOffset,
        nonceOffset,
        ctr,
      );
      return {
        ctr: ret,
        cipherText: Uint8Array.from(cipherText),
      };
    }
  });
}

export function poly1305({
  message,
  key,
}: {
  message: InputBuffer;
  key: InputBuffer;
}) {
  return u8AllocCtx((ctx) => {
    const messageOffset = ctx.write(message);
    const keyOffset = ctx.write(key);
    const mac = ctx.alloc(MAC_BYTES);
    wasm.crypto_poly1305(
      mac.byteOffset,
      messageOffset,
      message.length,
      keyOffset,
    );
    return mac;
  });
}

export class Poly1305 {
  private context: Uint8Array | null;
  constructor(key: InputBuffer) {
    this.context = u8AllocCtx((ctx) => {
      const keyOffset = ctx.write(key, { wipe: true });
      const context = ctx.alloc(poly1305CtxSize);
      wasm.crypto_poly1305_init(context.byteOffset, keyOffset);
      return context;
    });
  }

  update(message: InputBuffer): void {
    if (!this.context) {
      throw "Can't call after finalizing";
    }
    this.context = u8AllocCtx((ctx) => {
      const messageOffset = ctx.write(message, { wipe: true });
      const context = ctx.write(this.context!, { retBuffer: true });
      wasm.crypto_poly1305_update(context.byteOffset, messageOffset, message.length);
      return context;
    });
  }

  finalize(): Uint8Array {
    if (!this.context) {
      throw "Can't call after finalizing";
    }
    const mac = u8AllocCtx((ctx) => {
      const contextOffset = ctx.write(this.context!);
      const mac = ctx.alloc(MAC_BYTES);
      wasm.crypto_poly1305_final(contextOffset, mac.byteOffset);
      return mac;
    });
    this.context = null;
    return mac;
  }
}

export function elligatorMap(hidden: InputBuffer) {
  return u8AllocCtx((ctx) => {
    const hiddenOffset = ctx.write(hidden);
    const curve = ctx.alloc(KEY_BYTES);
    wasm.crypto_elligator_map(curve.byteOffset, hiddenOffset);
    return curve;
  });
}

export function elligatorRev({
  hidden,
  curve,
  tweak,
}: {
  hidden: InputBuffer;
  curve: InputBuffer;
  tweak: number;
}): number {
  return allocCtx((ctx) => {
    const hiddenOffset = ctx.write(hidden);
    const curveOffset = ctx.write(curve);
    return wasm.crypto_elligator_rev(hiddenOffset, curveOffset, tweak);
  });
}

export function elligatorKeyPair() {
  return allocCtx((ctx) => {
    const hidden = ctx.alloc(KEY_BYTES);
    const secretKey = ctx.alloc(KEY_BYTES);
    const seed = ctx.alloc(KEY_BYTES);
    wasm.crypto_elligator_key_pair(
      hidden.byteOffset,
      secretKey.byteOffset,
      seed.byteOffset,
    );
    return {
      hidden: Uint8Array.from(hidden),
      secretKey: Uint8Array.from(secretKey),
      seed: Uint8Array.from(seed),
    };
  });
}

// export function crypto_x25519(
//   your_secret_key: InputBuffer,
//   their_public_key: InputBuffer,
// ): Uint8Array {
//   const ptr = alloc(KEY_BYTES * 3);
//   if (your_secret_key) write(your_secret_key, ptr + KEY_BYTES);
//   if (their_public_key) write(their_public_key, ptr + KEY_BYTES * 2);
//   wasm.crypto_x25519(
//     ptr,
//     your_secret_key ? ptr + KEY_BYTES : 0,
//     their_public_key ? ptr + KEY_BYTES * 2 : 0,
//   );
//   return read(ptr, KEY_BYTES);
// }

// export function crypto_x25519_public_key(secret_key: InputBuffer): Uint8Array {
//   const ptr = alloc(KEY_BYTES * 2);
//   if (secret_key) write(secret_key, ptr + KEY_BYTES);
//   wasm.crypto_x25519_public_key(ptr, secret_key ? ptr + KEY_BYTES : 0);
//   wasm.crypto_wipe(ptr + KEY_BYTES, KEY_BYTES);
//   return read(ptr, KEY_BYTES);
// }

// export function crypto_blake2b(message: InputBuffer): Uint8Array {
//   const messageLength = message ? message.length : 0;
//   const ptr = alloc(HASH_BYTES + messageLength);
//   if (message) write(message, ptr + HASH_BYTES);
//   wasm.crypto_blake2b(ptr, message ? ptr + HASH_BYTES : 0, messageLength);
//   return read(ptr, HASH_BYTES);
// }
// export function crypto_blake2b_general(
//   hash_size: number,
//   key: InputBuffer,
//   message: InputBuffer,
// ): Uint8Array {
//   const keyLength = key ? key.length : 0;
//   const messageLength = message ? message.length : 0;
//   const ptr = alloc(hash_size + keyLength + messageLength);
//   if (key) write(key, ptr + hash_size);
//   if (message) write(message, ptr + hash_size + keyLength);
//   wasm.crypto_blake2b_general(
//     ptr,
//     hash_size,
//     key ? ptr + hash_size : 0,
//     keyLength,
//     message ? ptr + hash_size + keyLength : 0,
//     messageLength,
//   );
//   return read(ptr, hash_size);
// }

// export function crypto_chacha20(
//   plain_text: InputBuffer,
//   key: InputBuffer,
//   nonce: InputBuffer,
// ): Uint8Array {
//   const textLength = plain_text ? plain_text.length : 0;
//   const ptr = alloc(textLength + KEY_BYTES + CHACHA20_NONCE_BYTES);
//   if (plain_text) write(plain_text, ptr);
//   if (key) write(key, ptr + textLength);
//   if (nonce) write(nonce, ptr + textLength + KEY_BYTES);
//   wasm.crypto_chacha20(
//     ptr,
//     ptr,
//     textLength,
//     key ? ptr + textLength : 0,
//     nonce ? ptr + textLength + KEY_BYTES : 0,
//   );
//   wasm.crypto_wipe(ptr + textLength, KEY_BYTES);
//   return read(ptr, textLength);
// }
// export function crypto_xchacha20(
//   plain_text: InputBuffer,
//   key: InputBuffer,
//   nonce: InputBuffer,
// ): Uint8Array {
//   const textLength = plain_text ? plain_text.length : 0;
//   const ptr = alloc(textLength + KEY_BYTES + NONCE_BYTES);
//   if (plain_text) write(plain_text, ptr);
//   if (key) write(key, ptr + textLength);
//   if (nonce) write(nonce, ptr + textLength + KEY_BYTES);
//   wasm.crypto_xchacha20(
//     ptr,
//     ptr,
//     textLength,
//     key ? ptr + textLength : 0,
//     nonce ? ptr + textLength + KEY_BYTES : 0,
//   );
//   wasm.crypto_wipe(ptr + textLength, KEY_BYTES);
//   return read(ptr, textLength);
// }

// export function crypto_curve_to_hidden(curve: InputBuffer, tweak: number): Uint8Array | null {
//   const ptr = alloc(KEY_BYTES * 2);
//   if (curve) write(curve, ptr + KEY_BYTES);
//   const success = wasm.crypto_curve_to_hidden(ptr, curve ? ptr + KEY_BYTES : 0, tweak) === 0;
//   wasm.crypto_wipe(ptr + KEY_BYTES, KEY_BYTES);
//   return success ? read(ptr, KEY_BYTES) : null;
// }
// export function crypto_hidden_to_curve(hidden: InputBuffer): Uint8Array {
//   const ptr = alloc(KEY_BYTES * 2);
//   if (hidden) write(hidden, ptr + KEY_BYTES);
//   wasm.crypto_hidden_to_curve(ptr, hidden ? ptr + KEY_BYTES : 0);
//   wasm.crypto_wipe(ptr + KEY_BYTES, KEY_BYTES);
//   return read(ptr, KEY_BYTES);
// }
// export function crypto_hidden_key_pair(
//   seed: InputBuffer,
// ): { hidden: Uint8Array; secret_key: Uint8Array } {
//   const ptr = alloc(KEY_BYTES * 3);
//   if (seed) write(seed, ptr + KEY_BYTES * 2);
//   wasm.crypto_hidden_key_pair(ptr, ptr + KEY_BYTES, seed ? ptr + KEY_BYTES * 2 : 0);
//   const hidden = read(ptr, KEY_BYTES);
//   const secret_key = read(ptr + KEY_BYTES, KEY_BYTES);
//   wasm.crypto_wipe(ptr, KEY_BYTES * 3);
//   return { hidden, secret_key };
// }

// export function crypto_from_eddsa_private(eddsa: InputBuffer): Uint8Array {
//   const ptr = alloc(KEY_BYTES * 2);
//   if (eddsa) write(eddsa, ptr + KEY_BYTES);
//   wasm.crypto_from_eddsa_private(ptr, eddsa ? ptr + KEY_BYTES : 0);
//   wasm.crypto_wipe(ptr + KEY_BYTES, KEY_BYTES);
//   return read(ptr, KEY_BYTES);
// }
// export function crypto_from_eddsa_public(eddsa: InputBuffer): Uint8Array {
//   const ptr = alloc(KEY_BYTES * 2);
//   if (eddsa) write(eddsa, ptr + KEY_BYTES);
//   wasm.crypto_from_eddsa_public(ptr, eddsa ? ptr + KEY_BYTES : 0);
//   return read(ptr, KEY_BYTES);
// }

// export function crypto_hchacha20(key: InputBuffer, in_: InputBuffer): Uint8Array {
//   const ptr = alloc(KEY_BYTES * 2 + 16);
//   if (key) write(key, ptr + KEY_BYTES);
//   if (in_) write(in_, ptr + KEY_BYTES * 2);
//   wasm.crypto_hchacha20(ptr, key ? ptr + KEY_BYTES : 0, in_ ? ptr + KEY_BYTES * 2 : 0);
//   wasm.crypto_wipe(ptr + KEY_BYTES, KEY_BYTES + 16);
//   return read(ptr, KEY_BYTES);
// }

// export function crypto_ietf_chacha20(
//   plain_text: InputBuffer,
//   key: InputBuffer,
//   nonce: InputBuffer,
// ): Uint8Array {
//   const textLength = plain_text ? plain_text.length : 0;
//   const ptr = alloc(textLength + KEY_BYTES + 12);
//   if (plain_text) write(plain_text, ptr);
//   if (key) write(key, ptr + textLength);
//   if (nonce) write(nonce, ptr + textLength + KEY_BYTES);
//   wasm.crypto_ietf_chacha20(
//     ptr,
//     ptr,
//     textLength,
//     key ? ptr + textLength : 0,
//     nonce ? ptr + textLength + KEY_BYTES : 0,
//   );
//   wasm.crypto_wipe(ptr + textLength, KEY_BYTES);
//   return read(ptr, textLength);
// }

// export function crypto_key_exchange(
//   your_secret_key: InputBuffer,
//   their_public_key: InputBuffer,
// ): Uint8Array {
//   const ptr = alloc(KEY_BYTES * 3);
//   if (your_secret_key) write(your_secret_key, ptr + KEY_BYTES);
//   if (their_public_key) write(their_public_key, ptr + KEY_BYTES * 2);
//   wasm.crypto_key_exchange(
//     ptr,
//     your_secret_key ? ptr + KEY_BYTES : 0,
//     their_public_key ? ptr + KEY_BYTES * 2 : 0,
//   );
//   return read(ptr, KEY_BYTES);
// }
// export function crypto_key_exchange_public_key(your_secret_key: InputBuffer): Uint8Array {
//   return crypto_x25519_public_key(your_secret_key);
// }

// export function crypto_lock(
//   key: InputBuffer,
//   nonce: InputBuffer,
//   plain_text: InputBuffer,
// ): Uint8Array {
//   const textLength = plain_text ? plain_text.length : 0;
//   const ptr = alloc(MAC_BYTES + textLength + KEY_BYTES + NONCE_BYTES);
//   if (plain_text) write(plain_text, ptr + MAC_BYTES);
//   if (key) write(key, ptr + MAC_BYTES + textLength);
//   if (nonce) write(nonce, ptr + MAC_BYTES + textLength + KEY_BYTES);
//   wasm.crypto_lock(
//     ptr,
//     ptr + MAC_BYTES,
//     key ? ptr + MAC_BYTES + textLength : 0,
//     nonce ? ptr + MAC_BYTES + textLength + KEY_BYTES : 0,
//     ptr + MAC_BYTES,
//     textLength,
//   );
//   wasm.crypto_wipe(ptr + MAC_BYTES + textLength, KEY_BYTES);
//   return read(ptr, MAC_BYTES + textLength);
// }
// export function crypto_unlock(
//   key: InputBuffer,
//   nonce: InputBuffer,
//   cipher_text: InputBuffer,
// ): Uint8Array | null {
//   if (!cipher_text || cipher_text.length < MAC_BYTES) return null;
//   const textLength = cipher_text.length - MAC_BYTES;
//   const ptr = alloc(MAC_BYTES + textLength + KEY_BYTES + NONCE_BYTES);
//   write(cipher_text, ptr);
//   if (key) write(key, ptr + MAC_BYTES + textLength);
//   if (nonce) write(nonce, ptr + MAC_BYTES + textLength + KEY_BYTES);
//   const success = wasm.crypto_unlock(
//     ptr + MAC_BYTES,
//     key ? ptr + MAC_BYTES + textLength : 0,
//     nonce ? ptr + MAC_BYTES + textLength + KEY_BYTES : 0,
//     ptr,
//     ptr + MAC_BYTES,
//     textLength,
//   ) === 0;
//   wasm.crypto_wipe(ptr + MAC_BYTES + textLength, KEY_BYTES);
//   return success ? read(ptr + MAC_BYTES, textLength) : null;
// }
// export function crypto_lock_aead(
//   key: InputBuffer,
//   nonce: InputBuffer,
//   ad: InputBuffer,
//   plain_text: InputBuffer,
// ): Uint8Array {
//   const textLength = plain_text ? plain_text.length : 0;
//   const adLength = ad ? ad.length : 0;
//   const ptr = alloc(MAC_BYTES + textLength + KEY_BYTES + NONCE_BYTES + adLength);
//   if (plain_text) write(plain_text, ptr + MAC_BYTES);
//   if (key) write(key, ptr + MAC_BYTES + textLength);
//   if (nonce) write(nonce, ptr + MAC_BYTES + textLength + KEY_BYTES);
//   if (ad) write(ad, ptr + MAC_BYTES + textLength + KEY_BYTES + NONCE_BYTES);
//   wasm.crypto_lock_aead(
//     ptr,
//     ptr + MAC_BYTES,
//     key ? ptr + MAC_BYTES + textLength : 0,
//     nonce ? ptr + MAC_BYTES + textLength + KEY_BYTES : 0,
//     ad ? ptr + MAC_BYTES + textLength + KEY_BYTES + NONCE_BYTES : 0,
//     adLength,
//     ptr + MAC_BYTES,
//     textLength,
//   );
//   wasm.crypto_wipe(ptr + MAC_BYTES + textLength, KEY_BYTES);
//   return read(ptr, MAC_BYTES + textLength);
// }
// export function crypto_unlock_aead(
//   key: InputBuffer,
//   nonce: InputBuffer,
//   ad: InputBuffer,
//   cipher_text: InputBuffer,
// ): Uint8Array | null {
//   if (!cipher_text || cipher_text.length < MAC_BYTES) return null;
//   const textLength = cipher_text.length - MAC_BYTES;
//   const adLength = ad ? ad.length : 0;
//   const ptr = alloc(MAC_BYTES + textLength + KEY_BYTES + NONCE_BYTES + adLength);
//   write(cipher_text ?? [], ptr);
//   if (key) write(key, ptr + MAC_BYTES + textLength);
//   if (nonce) write(nonce, ptr + MAC_BYTES + textLength + KEY_BYTES);
//   if (ad) write(ad, ptr + MAC_BYTES + textLength + KEY_BYTES + NONCE_BYTES);
//   const success = wasm.crypto_unlock_aead(
//     ptr + MAC_BYTES,
//     key ? ptr + MAC_BYTES + textLength : 0,
//     nonce ? ptr + MAC_BYTES + textLength + KEY_BYTES : 0,
//     ptr,
//     ad ? ptr + MAC_BYTES + textLength + KEY_BYTES + NONCE_BYTES : 0,
//     adLength,
//     ptr + MAC_BYTES,
//     textLength,
//   ) === 0;
//   wasm.crypto_wipe(ptr + MAC_BYTES + textLength, KEY_BYTES);
//   return success ? read(ptr + MAC_BYTES, textLength) : null;
// }

// export function crypto_poly1305(message: InputBuffer, key: InputBuffer): Uint8Array {
//   const messageLength = message ? message.length : 0;
//   const ptr = alloc(MAC_BYTES + KEY_BYTES + messageLength);
//   write(key ?? [], ptr + MAC_BYTES);
//   if (message) write(message, ptr + MAC_BYTES + KEY_BYTES);
//   wasm.crypto_poly1305(ptr, ptr + MAC_BYTES + KEY_BYTES, messageLength, ptr + MAC_BYTES);
//   return read(ptr, MAC_BYTES);
// }

// export function crypto_sign_public_key(secret_key: InputBuffer): Uint8Array {
//   const ptr = alloc(KEY_BYTES * 2);
//   if (secret_key) write(secret_key, ptr + KEY_BYTES);
//   wasm.crypto_sign_public_key(ptr, secret_key ? ptr + KEY_BYTES : 0);
//   wasm.crypto_wipe(ptr + KEY_BYTES, KEY_BYTES);
//   return read(ptr, secret_key ? KEY_BYTES : 0);
// }
// export function crypto_sign(
//   secret_key: InputBuffer,
//   public_key: InputBuffer,
//   message: InputBuffer,
// ): Uint8Array {
//   const messageLength = message ? message.length : 0;
//   const ptr = alloc(HASH_BYTES + KEY_BYTES + KEY_BYTES + messageLength);
//   if (secret_key) write(secret_key, ptr + HASH_BYTES);
//   if (public_key) write(public_key, ptr + HASH_BYTES + KEY_BYTES);
//   if (message) write(message, ptr + HASH_BYTES + KEY_BYTES * 2);
//   wasm.crypto_sign(
//     ptr,
//     secret_key ? ptr + HASH_BYTES : 0,
//     public_key ? ptr + HASH_BYTES + KEY_BYTES : 0,
//     message ? ptr + HASH_BYTES + KEY_BYTES * 2 : 0,
//     messageLength,
//   );
//   wasm.crypto_wipe(ptr + HASH_BYTES + KEY_BYTES, KEY_BYTES);
//   return read(ptr, HASH_BYTES);
// }
// export function crypto_check(
//   signature: InputBuffer,
//   public_key: InputBuffer,
//   message: InputBuffer,
// ): boolean {
//   const messageLength = message ? message.length : 0;
//   const ptr = alloc(HASH_BYTES + KEY_BYTES + messageLength);
//   if (signature) write(signature, ptr, HASH_BYTES);
//   if (public_key) write(public_key, ptr + HASH_BYTES, KEY_BYTES);
//   if (message) write(message, ptr + HASH_BYTES + KEY_BYTES, messageLength);
//   return wasm.crypto_check(
//     signature ? ptr : 0,
//     public_key ? ptr + HASH_BYTES : 0,
//     message ? ptr + HASH_BYTES + KEY_BYTES : 0,
//     messageLength,
//   ) === 0;
// }

// export function crypto_verify16(a: InputBuffer, b: InputBuffer): boolean {
//   const ptr = alloc(32);
//   write(a ?? [], ptr);
//   write(b ?? [], ptr + 16);
//   return wasm.crypto_verify16(ptr, ptr + 16) === 0;
// }
// export function crypto_verify32(a: InputBuffer, b: InputBuffer): boolean {
//   const ptr = alloc(64);
//   write(a ?? [], ptr);
//   write(b ?? [], ptr + 32);
//   return wasm.crypto_verify32(ptr, ptr + 32) === 0;
// }
// export function crypto_verify64(a: InputBuffer, b: InputBuffer): boolean {
//   const ptr = alloc(128);
//   write(a ?? [], ptr);
//   write(b ?? [], ptr + 64);
//   return wasm.crypto_verify64(ptr, ptr + 64) === 0;
// }

// export function crypto_x25519(
//   your_secret_key: InputBuffer,
//   their_public_key: InputBuffer,
// ): Uint8Array {
//   const ptr = alloc(KEY_BYTES * 3);
//   if (your_secret_key) write(your_secret_key, ptr + KEY_BYTES);
//   if (their_public_key) write(their_public_key, ptr + KEY_BYTES * 2);
//   wasm.crypto_x25519(
//     ptr,
//     your_secret_key ? ptr + KEY_BYTES : 0,
//     their_public_key ? ptr + KEY_BYTES * 2 : 0,
//   );
//   return read(ptr, KEY_BYTES);
// }
// export function crypto_x25519_public_key(secret_key: InputBuffer): Uint8Array {
//   const ptr = alloc(KEY_BYTES * 2);
//   if (secret_key) write(secret_key, ptr + KEY_BYTES);
//   wasm.crypto_x25519_public_key(ptr, secret_key ? ptr + KEY_BYTES : 0);
//   wasm.crypto_wipe(ptr + KEY_BYTES, KEY_BYTES);
//   return read(ptr, KEY_BYTES);
// }

// export function crypto_x25519_dirty_fast(secret_key: InputBuffer): Uint8Array {
//   const ptr = alloc(KEY_BYTES * 2);
//   if (secret_key) write(secret_key, ptr + KEY_BYTES);
//   wasm.crypto_x25519_dirty_fast(ptr, secret_key ? ptr + KEY_BYTES : 0);
//   wasm.crypto_wipe(ptr + KEY_BYTES, KEY_BYTES);
//   return read(ptr, KEY_BYTES);
// }
// export function crypto_x25519_dirty_small(secret_key: InputBuffer): Uint8Array {
//   const ptr = alloc(KEY_BYTES * 2);
//   if (secret_key) write(secret_key, ptr + KEY_BYTES);
//   wasm.crypto_x25519_dirty_small(ptr, secret_key ? ptr + KEY_BYTES : 0);
//   wasm.crypto_wipe(ptr + KEY_BYTES, KEY_BYTES);
//   return read(ptr, KEY_BYTES);
// }

// export function crypto_x25519_inverse(
//   private_key: InputBuffer,
//   curve_point: InputBuffer,
// ): Uint8Array {
//   const ptr = alloc(KEY_BYTES * 3);
//   if (private_key) write(private_key, ptr + KEY_BYTES);
//   if (curve_point) write(curve_point, ptr + KEY_BYTES * 2);
//   wasm.crypto_x25519_inverse(
//     ptr,
//     private_key ? ptr + KEY_BYTES : 0,
//     curve_point ? ptr + KEY_BYTES * 2 : 0,
//   );
//   wasm.crypto_wipe(ptr + KEY_BYTES, KEY_BYTES);
//   return read(ptr, KEY_BYTES);
// }
