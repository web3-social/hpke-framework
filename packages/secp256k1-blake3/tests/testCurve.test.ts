import { assert, describe, it } from 'vitest'
import * as secp256k1 from 'secp256k1'
import { randomBytes } from 'crypto'
import { hash } from '@web3-social/blake3-hkdf-js'

describe('secp256k1', () => {
    it('secp256k1 hash length', () => {
        const key1 = randomBytes(32)
        const pub1 = secp256k1.publicKeyCreate(key1, false)

        const key2 = randomBytes(32)
        const pub2 = secp256k1.publicKeyCreate(key2, false)

        const output1 = new Uint8Array(32)
        secp256k1.ecdh(
            pub2,
            key1,
            {
                data: new Uint8Array(64),
                hashfn: (x, y, data) => {
                    data.set(x)
                    data.set(y, 32)
                    return hash(data)
                },
            },
            output1,
        )
        const output2 = new Uint8Array(32)
        secp256k1.ecdh(
            pub1,
            key2,
            {
                data: new Uint8Array(64),
                hashfn: (x, y, data) => {
                    data.set(x)
                    data.set(y, 32)
                    return hash(data)
                },
            },
            output2,
        )
        assert(Buffer.from(output1).toString('hex') == Buffer.from(output2).toString('hex'))
    })
})
