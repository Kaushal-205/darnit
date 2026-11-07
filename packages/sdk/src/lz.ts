/**
 * FastLZ (LZ77) compression matching Solady's `LibZip.flzDecompress`, which Smart Sessions uses to unpack
 * USE-mode signatures. Ported line for line from Solady's js/solady.js (MIT, Copyright (c) 2022 Solady),
 * including its floating-point hash, so the output is byte-identical to the reference implementation.
 */
import { type Hex, bytesToHex, hexToBytes } from "viem";

export function flzCompress(data: Hex): Hex {
  const ib = hexToBytes(data);
  const b = ib.length - 4;
  const ht: number[] = [];
  const ob: number[] = [];
  let a = 0;
  let i = 2;
  let o = 0;
  let s = 0;
  let h = 0;
  let d = 0;
  let c = 0;
  let l = 0;
  let r = 0;

  const u24 = (x: number) => ib[x] | (ib[x + 1] << 8) | (ib[x + 2] << 16);
  const hash = (x: number) => ((2654435769 * x) >> 19) & 8191;
  const literals = (count: number, start: number) => {
    let n = count;
    let src = start;
    while (n >= 32) {
      ob[o++] = 31;
      for (let j = 32; j--; n--) ob[o++] = ib[src++];
    }
    if (n) {
      ob[o++] = n - 1;
      while (n--) ob[o++] = ib[src++];
    }
  };

  while (i < b - 9) {
    do {
      s = u24(i);
      h = hash(s);
      r = ht[h] || 0;
      ht[h] = i;
      d = i - r;
      c = d < 8192 ? u24(r) : 0x1000000;
    } while (i < b - 9 && i++ && s !== c);
    if (i >= b - 9) break;
    if (--i > a) literals(i - a, a);
    const p = r + 3;
    const q = i + 3;
    let e = b - q;
    for (l = 0; l < e; l++) e *= ib[p + l] === ib[q + l] ? 1 : 0;
    i += l;
    for (--d; l > 262; l -= 262) {
      ob[o++] = 224 + (d >> 8);
      ob[o++] = 253;
      ob[o++] = d & 255;
    }
    if (l < 7) {
      ob[o++] = (l << 5) + (d >> 8);
      ob[o++] = d & 255;
    } else {
      ob[o++] = 224 + (d >> 8);
      ob[o++] = l - 7;
      ob[o++] = d & 255;
    }
    ht[hash(u24(i))] = i++;
    ht[hash(u24(i))] = i++;
    a = i;
  }
  literals(b + 4 - a, a);
  return bytesToHex(Uint8Array.from(ob));
}

export function flzDecompress(data: Hex): Hex {
  const ib = hexToBytes(data);
  const ob: number[] = [];
  let i = 0;
  let o = 0;
  while (i < ib.length) {
    const t = ib[i] >> 5;
    if (!t) {
      for (let l = 1 + ib[i++]; l--; ) ob[o++] = ib[i++];
    } else {
      const short = t < 7 ? 1 : 0;
      const f = 256 * (ib[i] & 31) + ib[i + 2 - short];
      let l = short ? 2 + (ib[i] >> 5) : 9 + ib[i + 1];
      i = i + 3 - short;
      let r = o - f - 1;
      while (l--) ob[o++] = ob[r++];
    }
  }
  return bytesToHex(Uint8Array.from(ob));
}
