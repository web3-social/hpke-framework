import { getCrypto, KdfContext, type KdfFactory } from '@web3-social/hpke-framework'
import { hmac } from './hmac'

const crypto = getCrypto()

export const HkdfFactory = async (hash: string, kdfId?: number, nH?: number): Promise<KdfFactory> => {
    switch (hash) {
        case 'SHA-256':
            nH = 32
            kdfId = 0x0001
            break
        case 'SHA-384':
            nH = 48
            kdfId = 0x0002
            break
        case 'SHA-512':
            nH = 64
            kdfId = 0x0003
            break
        default:
            const detectKey = await crypto.subtle.generateKey(
                {
                    name: 'HMAC',
                    hash: { name: hash },
                },
                true,
                ['sign'],
            )
            const detectLength = await hmac(detectKey, new Uint8Array(10))
            nH = detectLength.byteLength
            if (kdfId === undefined) {
                kdfId = 0xffff
            }
    }

    const factory = ((suiteId: Uint8Array) => {
        return new HkdfContext(hash, nH!, kdfId!, suiteId) as KdfContext
    }) as KdfFactory
    factory.kdfId = kdfId
    return factory
}

export class HkdfError extends Error {}

export class HkdfContext extends KdfContext {
    private readonly hash: string

    constructor(hash: string, nH: number, kdfId: number, suitId: Uint8Array) {
        super(nH, kdfId, suitId)
        this.hash = hash
    }

    public async extract(salt: Uint8Array, ikm: Uint8Array): Promise<Uint8Array> {
        if (salt.length === 0) {
            salt = new Uint8Array(this.nH)
        }
        const key = await crypto.subtle.importKey(
            'raw',
            salt,
            {
                name: 'HMAC',
                hash: this.hash,
            },
            false,
            ['sign'],
        )
        const prk = await hmac(key, ikm)
        return new Uint8Array(prk)
    }

    public async expand(prk: Uint8Array, info: Uint8Array, l: number): Promise<Uint8Array> {
        const steps = Math.ceil(this.nH / l)
        if (steps > 0xff) throw new HkdfError(`l = ${l} is too long for expand`)

        const key = await crypto.subtle.importKey(
            'raw',
            prk,
            {
                name: 'HMAC',
                hash: this.hash,
            },
            false,
            ['sign'],
        )

        const okm = new ArrayBuffer(l)
        const p = new Uint8Array(okm)
        let prev = new Uint8Array(0)
        const mid = new Uint8Array(info)
        const tail = new Uint8Array(1)

        const tmp = new Uint8Array(this.nH + mid.length + 1)
        for (let i = 1, cur = 0; cur < p.length; i++) {
            tail[0] = i
            tmp.set(prev, 0)
            tmp.set(mid, prev.length)
            tmp.set(tail, prev.length + mid.length)
            prev = await hmac(key, tmp.slice(0, prev.length + mid.length + 1))
            if (p.length - cur >= prev.length) {
                p.set(prev, cur)
                cur += prev.length
            } else {
                p.set(prev.slice(0, p.length - cur), cur)
                cur += p.length - cur
            }
        }
        return new Uint8Array(okm)
    }
}
