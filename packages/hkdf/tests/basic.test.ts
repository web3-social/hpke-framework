import { describe, expect, it } from 'vitest'
import { hmac } from '../src/hmac'
import { arrayFromHex, getCrypto } from '@web3-social/hpke-framework'
import { HkdfContext, HkdfFactory } from '../src'

const crypto = getCrypto()

const asHmacKey = (key: Uint8Array, hash: string) => {
    return crypto.subtle.importKey(
        'raw',
        key,
        {
            name: 'HMAC',
            hash: { name: hash },
        },
        false,
        ['sign', 'verify'],
    )
}

describe('HMAC Correctness', () => {
    it('Test Case 1', async () => {
        const key = arrayFromHex('0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b')
        const data = arrayFromHex('4869205468657265')

        expect(new Uint8Array(await hmac(await asHmacKey(key, 'SHA-256'), data))).toEqual(
            arrayFromHex('b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7'),
        )

        expect(new Uint8Array(await hmac(await asHmacKey(key, 'SHA-384'), data))).toEqual(
            arrayFromHex(
                'afd03944d84895626b0825f4ab46907f15f9dadbe4101ec682aa034c7cebc59cfaea9ea9076ede7f4af152e8b2fa9cb6',
            ),
        )

        expect(new Uint8Array(await hmac(await asHmacKey(key, 'SHA-512'), data))).toEqual(
            arrayFromHex(
                '87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cdedaa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854',
            ),
        )
    })
})

describe('HKDF Correctness', () => {
    it('Test Case 1: Basic test case with SHA-256', async () => {
        const kdf = new HkdfContext('SHA-256', 32, 0x0001, new Uint8Array())
        const salt = arrayFromHex('0x000102030405060708090a0b0c')
        const ikm = arrayFromHex('0x0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b')

        const prk = await kdf.extract(salt, ikm)
        expect(prk).toEqual(arrayFromHex('0x077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5'))

        const info = arrayFromHex('0xf0f1f2f3f4f5f6f7f8f9')
        const okm = await kdf.expand(prk, info, 42)
        expect(okm).toEqual(
            arrayFromHex('0x3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865'),
        )
    })

    it('Test Case 2: Test with SHA-256 and longer inputs/outputs', async () => {
        const kdf = new HkdfContext('SHA-256', 32, 0x0001, new Uint8Array())
        const salt = arrayFromHex(
            '0x606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeaf',
        )
        const ikm = arrayFromHex(
            '0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f',
        )

        const prk = await kdf.extract(salt, ikm)
        expect(prk).toEqual(arrayFromHex('0x06a6b88c5853361a06104c9ceb35b45cef760014904671014a193f40c15fc244'))

        const info = arrayFromHex(
            '0xb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff',
        )
        const okm = await kdf.expand(prk, info, 82)
        expect(okm).toEqual(
            arrayFromHex(
                '0xb11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71cc30c58179ec3e87c14c01d5c1f3434f1d87',
            ),
        )
    })

    it('Test Case 3: Test with SHA-256 and zero-length salt/info', async () => {
        const kdf = new HkdfContext('SHA-256', 32, 0x0001, new Uint8Array())
        const salt = new Uint8Array()
        const ikm = arrayFromHex('0x0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b')

        const prk = await kdf.extract(salt, ikm)
        expect(prk).toEqual(arrayFromHex('0x19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04'))

        const info = new Uint8Array()
        expect(await kdf.expand(prk, info, 42)).toEqual(
            arrayFromHex('0x8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8'),
        )
    })
})

describe('HKDF Factory', () => {
    it('Test Case 1: SHA-256', async () => {
        const factory = await HkdfFactory('SHA-256')
        const kdf = factory(new Uint8Array())
        expect(kdf.nH).toEqual(32)
        expect(kdf.kdfId).toEqual(0x0001)
    })

    it('Test Case 2: SHA-384', async () => {
        const factory = await HkdfFactory('SHA-384')
        const kdf = factory(new Uint8Array())
        expect(kdf.nH).toEqual(48)
        expect(kdf.kdfId).toEqual(0x0002)
    })


    it('Test Case 3: SHA-512', async () => {
        const factory = await HkdfFactory('SHA-512')
        const kdf = factory(new Uint8Array())
        expect(kdf.nH).toEqual(64)
        expect(kdf.kdfId).toEqual(0x0003)
    })


    it('Test Case 4: Detect Key', async () => {
        const factory = await HkdfFactory('SHA-1')
        const kdf = factory(new Uint8Array())
        expect(kdf.nH).toEqual(20)
        expect(kdf.kdfId).toEqual(0xffff)
    })

    it('Test Case 5: Unsupported', async () => {
        expect(HkdfFactory('MD5')).rejects.toThrowError()
    })
})