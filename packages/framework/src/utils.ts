import {HpkeError, I2OspError, Os2IpError} from './errors.js';

/**
 * Convert non-negative integer n to a w-length, big-endian byte string, as described in [RFC8017]
 *
 * @param n - non-negative integer
 * @param w - length of byte string
 * @returns byte string
 * @throws I2OspError
 */
export function i2osp(n: number, w: number): Uint8Array {
    if (n < 0) {
        throw new I2OspError('n must be non-negative');
    }
    if (w < 0) {
        throw new I2OspError('w must be non-negative');
    }
    const b = new Uint8Array(w);
    for (let i = w - 1; i >= 0; i--) {
        b[i] = n & 0xff;
        n = n >> 8;
    }
    if (n !== 0) {
        throw new I2OspError('n is too large');
    }
    return b;
}

/**
 * Convert byte string x to a non-negative integer, as described in [RFC8017], assuming big-endian byte order.
 *
 * @param x - byte string
 * @returns non-negative integer
 * @throws Os2IpError
 */
export function os2ip(x: Uint8Array): number {
    if (x.length === 0) {
        throw new Os2IpError('os2ip: x must not be empty');
    }
    let n = 0;
    for (let i = 0; i < x.length; i++) {
        n = n << 8;
        n = n | x[i]!;
    }
    return n;
}

/**
 * Build Uint8Array from ascii string
 */
export function arrayFromAscii(ascii: string): Uint8Array {
    const bytes = new Uint8Array(ascii.length);
    for (let i = 0; i < ascii.length; i++) {
        bytes[i] = ascii.charCodeAt(i);
    }
    return bytes;
}

const isHex = /^[0-9A-Fa-f]+$/;

/**
 * Convert hex string to Uint8Array
 */
export function arrayFromHex(hex: string): Uint8Array {
    hex = hex.startsWith('0x') || hex.startsWith('0X') ? hex.slice(2) : hex;
    if (!(hex.length % 2 == 0 && isHex.test(hex))) throw new Error('Invalid hex string');
    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < hex.length; i += 2) {
        bytes[i / 2] = parseInt(hex.slice(i, i + 2), 16);
    }
    return bytes;
}

export function concatUint8Array(...arrays: Uint8Array[]): Uint8Array {
    const totalLength = arrays.reduce((prev, curr) => prev + curr.length, 0);
    const result = new Uint8Array(totalLength);

    let offset = 0;
    for (const array of arrays) {
        result.set(array, offset);
        offset += array.length;
    }

    return result;
}

/**
 * Executes XOR of two byte strings.
 */
export function xor(a: Uint8Array, b: Uint8Array): Uint8Array {
    if (a.byteLength !== b.byteLength) {
        throw new Error('xor: different length inputs');
    }
    const buf = new Uint8Array(a.byteLength);
    for (let i = 0; i < a.byteLength; i++) {
        buf[i] = a[i]! ^ b[i]!;
    }
    return buf;
}

export function getCrypto(): Crypto {
    try {
        if (globalThis.crypto !== undefined) {
            return globalThis.crypto;
        }
    } catch (_) { /* ignore */ }
    throw new HpkeError("Web Cryptography API not supported");
}