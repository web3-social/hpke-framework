import { Blake3 } from '@web3-social/blake3'

export function hmac(key: Uint8Array, message: Uint8Array): Uint8Array {
    const derKey = new Uint8Array(Blake3.BLOCK_LEN)
    if (key.length <= Blake3.BLOCK_LEN) {
        derKey.set(key)
    } else {
        const hash = Blake3.hash(key)
        derKey.set(hash)
    }

    const bufferSize = Blake3.BLOCK_LEN + Math.max(message.length, Blake3.OUT_LEN)
    const buffer = new Uint8Array(bufferSize)
    buffer.set(derKey.map((e) => e ^ 0x36)) // ipad
    buffer.set(message, Blake3.BLOCK_LEN)
    const hash1 = Blake3.hash(buffer.slice(0, Blake3.BLOCK_LEN + message.length))
    buffer.set(derKey.map((e) => e ^ 0x5c)) // opad
    buffer.set(hash1, Blake3.BLOCK_LEN)
    return Blake3.hash(buffer.slice(0, Blake3.BLOCK_LEN + Blake3.OUT_LEN))
}
