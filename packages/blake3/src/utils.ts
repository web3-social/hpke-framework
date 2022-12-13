import * as consts from './consts'

function rightRotate32(x: number, n: number): number {
    return ((x << (32 - n)) & 0xffffffff) | (x >>> n)
}

// The mixing function, G, which mixes either a column or a diagonal.
function g(state: Uint32Array, a: number, b: number, c: number, d: number, mx: number, my: number) {
    state[a] = (state[a]! + state[b]! + mx) & 0xffffffff
    state[d] = rightRotate32(state[d]! ^ state[a]!, 16)
    state[c] = (state[c]! + state[d]!) & 0xffffffff
    state[b] = rightRotate32(state[b]! ^ state[c]!, 12)
    state[a] = (state[a]! + state[b]! + my) & 0xffffffff
    state[d] = rightRotate32(state[d]! ^ state[a]!, 8)
    state[c] = (state[c]! + state[d]!) & 0xffffffff
    state[b] = rightRotate32(state[b]! ^ state[c]!, 7)
}

function round(state: Uint32Array, m: Uint32Array) {
    // Mix the columns.
    g(state, 0, 4, 8, 12, m[0]!, m[1]!)
    g(state, 1, 5, 9, 13, m[2]!, m[3]!)
    g(state, 2, 6, 10, 14, m[4]!, m[5]!)
    g(state, 3, 7, 11, 15, m[6]!, m[7]!)
    // Mix the diagonals.
    g(state, 0, 5, 10, 15, m[8]!, m[9]!)
    g(state, 1, 6, 11, 12, m[10]!, m[11]!)
    g(state, 2, 7, 8, 13, m[12]!, m[13]!)
    g(state, 3, 4, 9, 14, m[14]!, m[15]!)
}

function permute(m: Uint32Array) {
    const original = Uint32Array.from(m)
    for (let i = 0; i < 16; i++) {
        m[i] = original[consts.MSG_PERMUTATION[i]!]!
    }
}

const compressBuffer = new Uint32Array(16)
export function compress(
    chainingValue: Uint32Array,
    blockWords: Uint32Array,
    counterHi: number,
    counterLo: number,
    block_len: number,
    flags: number,
): Uint32Array {
    compressBuffer.set([
        chainingValue[0]!,
        chainingValue[1]!,
        chainingValue[2]!,
        chainingValue[3]!,
        chainingValue[4]!,
        chainingValue[5]!,
        chainingValue[6]!,
        chainingValue[7]!,
        consts.IV[0]!,
        consts.IV[1]!,
        consts.IV[2]!,
        consts.IV[3]!,
        counterLo,
        counterHi,
        block_len,
        flags,
    ])

    const block = Uint32Array.from(blockWords) // necessary copy

    round(compressBuffer, block) // round 1
    permute(block)
    round(compressBuffer, block) // round 2
    permute(block)
    round(compressBuffer, block) // round 3
    permute(block)
    round(compressBuffer, block) // round 4
    permute(block)
    round(compressBuffer, block) // round 5
    permute(block)
    round(compressBuffer, block) // round 6
    permute(block)
    round(compressBuffer, block) // round 7

    for (let i = 0; i < 8; i++) {
        compressBuffer[i] ^= compressBuffer[i + 8]!
        compressBuffer[i + 8] ^= chainingValue[i]!
    }
    return compressBuffer
}

export function wordsFromLittleEndianBytes(b: Uint8Array): Uint32Array {
    return new Uint32Array(b.buffer, b.byteOffset, b.byteLength / 4)
}
