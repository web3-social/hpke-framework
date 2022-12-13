import { KdfContext, type KdfFactory } from '@web3-social/hpke-framework'
import { hmac } from './hmac'

export class HkdfBlake3Error extends Error {}

const HKDF_BLAKE3_EXTRACT_SIZE = 32
const HKDF_BLAKE3_ID = 0xffff
export const HkdfBlake3Factory: KdfFactory = (() => {
    const factory = ((suiteId: Uint8Array) => {
        return new HkdfBlake3Context(suiteId) as KdfContext
    }) as KdfFactory
    factory.kdfId = HKDF_BLAKE3_ID
    return factory
})()

export class HkdfBlake3Context extends KdfContext {
    constructor(suitId: Uint8Array) {
        super(HKDF_BLAKE3_EXTRACT_SIZE, 0xff, suitId)
    }

    public async extract(salt: Uint8Array, ikm: Uint8Array): Promise<Uint8Array> {
        return hmac(salt, ikm)
    }

    public async expand(prk: Uint8Array, info: Uint8Array, l: number): Promise<Uint8Array> {
        const steps = Math.ceil(this.nH / l)
        if (steps > 0xff) throw new HkdfBlake3Error(`l = ${l} is too long for expand`)

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
            prev = hmac(prk, tmp.slice(0, prev.length + mid.length + 1))
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
