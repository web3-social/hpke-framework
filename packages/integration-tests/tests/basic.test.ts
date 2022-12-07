import { describe, expect, it } from 'vitest'
import { CipherSuite, HpkeMode, XCryptoKey, getCrypto } from '@web3-social/hpke-framework'
import { Secp256k1Blake3Kem } from '@web3-social/hpke-secp256k1-blake3'
import { HkdfBlake3Factory } from '@web3-social/hpke-hkdf-blake3'
import { Aes128GcmAead, Aes256GcmAead } from '@web3-social/hpke-aes-gcm'

const crypto = getCrypto()

describe('cipher suite base mode', () => {
    const baseTest = async (cipherSuite: CipherSuite) => {
        const { privateKey: skR, publicKey: pkR } = await cipherSuite.kem.generateKeyPair()

        const randomSize = (min: number, max: number) => Math.floor(Math.random() * (max - min + 1)) + min

        for (let i = 0; i < 10; i++) {
            const { enc, ctx: contextS } = await cipherSuite.createSenderContext({
                mode: HpkeMode.Base,
                pkR: pkR as XCryptoKey,
            })

            const PT = [...Array(10).keys()].map(() => {
                const pt = new Uint8Array(randomSize(1, 1024))
                crypto.getRandomValues(pt)
                return pt
            })

            const ct = await Promise.all(PT.map((pt) => contextS.seal(pt)))

            const contextR = await cipherSuite.createReceiverContext({
                mode: HpkeMode.Base,
                enc,
                skR: skR as XCryptoKey,
            })

            const pt = await Promise.all(ct.map((ct) => contextR.open(ct)))

            expect(pt).toEqual(PT)
        }
    }

    it('aes128', async () => {
        await baseTest(
            new CipherSuite({
                kem: new Secp256k1Blake3Kem(),
                kdfFactory: HkdfBlake3Factory,
                aead: new Aes128GcmAead(),
            }),
        )
    })

    it('aes256', async () => {
        await baseTest(
            new CipherSuite({
                kem: new Secp256k1Blake3Kem(),
                kdfFactory: HkdfBlake3Factory,
                aead: new Aes256GcmAead(),
            }),
        )
    })
})
