import {
    arrayFromAscii,
    DhKemContext,
    getCrypto,
    KdfContext,
    KdfFactory,
    XCryptoKey,
} from '@web3-social/hpke-framework'
import * as secp256k1 from '@noble/secp256k1'
import { HkdfContext } from '@web3-social/hpke-hkdf'

const ALGORITHM_NAME = 'secp256k1'
const SECP256K1_PRIVATE_KEY_LENGTH = 32
const SECP256K1_PUBLIC_KEY_LENGTH = 33
const SECP256K1_SHA256_KEM_ID = 0x6b32
const SECP256K1_DH_LENGTH = 32
const SECP256K1_SHA256_DERIVE_INFO = arrayFromAscii('DHKEM(secp256k1, SHA-256) deriveKey')

const crypto = getCrypto()

export class Secp256k1Sha256Kem extends DhKemContext {
    constructor() {
        const factory = ((suiteId: Uint8Array) => {
            return new HkdfContext('SHA-256', 32, 0x0001, suiteId) as KdfContext
        }) as KdfFactory
        factory.kdfId = 0x0001

        super({
            nSecret: SECP256K1_DH_LENGTH,
            nPk: SECP256K1_PUBLIC_KEY_LENGTH,
            nSk: SECP256K1_PRIVATE_KEY_LENGTH,
            nDh: SECP256K1_DH_LENGTH,
            kemId: SECP256K1_SHA256_KEM_ID,
            kdfFactory: factory,
        })
    }

    public async generateKeyPair(): Promise<CryptoKeyPair> {
        return this.keyPairFromRawPrivateKey(secp256k1.utils.randomPrivateKey())
    }
    public async deriveKeyPair(ikm: Uint8Array): Promise<CryptoKeyPair> {
        const baseKey = await crypto.subtle.importKey('raw', ikm, 'HKDF', false, ['deriveBits'])
        const bits = await crypto.subtle.deriveBits(
            {
                name: 'HKDF',
                hash: 'SHA-256',
                info: SECP256K1_SHA256_DERIVE_INFO,
            },
            baseKey,
            SECP256K1_PRIVATE_KEY_LENGTH + 16,
        )
        return this.keyPairFromRawPrivateKey(secp256k1.utils.hashToPrivateKey(new Uint8Array(bits)))
    }
    public async serializePublicKey(pkX: XCryptoKey): Promise<Uint8Array> {
        return pkX.key
    }
    public async deserializePublicKey(pkXm: Uint8Array): Promise<XCryptoKey> {
        return new XCryptoKey({
            algorithm: { name: ALGORITHM_NAME },
            key: pkXm,
            type: 'public',
        })
    }
    public async serializePrivateKey(skX: XCryptoKey): Promise<Uint8Array> {
        return skX.key
    }
    public async deserializePrivateKey(skXm: Uint8Array): Promise<XCryptoKey> {
        return new XCryptoKey({
            algorithm: { name: ALGORITHM_NAME },
            key: skXm,
            type: 'private',
        })
    }

    public async getPublicKeyFromPrivateKey(pkX: XCryptoKey): Promise<XCryptoKey> {
        const raw = secp256k1.getPublicKey(pkX.key, true)
        return new XCryptoKey({
            algorithm: { name: ALGORITHM_NAME },
            key: raw,
            type: 'public',
        })
    }

    /**
     * Perform a non-interactive Diffie-Hellman exchange using the private key skX and public key pkY
     * to produce a Diffie-Hellman shared secret of length `nDh`.
     *
     * @param skX private key
     * @param pkY public key
     * @returns shared secret
     * @throws ValidationError
     */
    public async dh(skX: XCryptoKey, pkY: XCryptoKey): Promise<Uint8Array> {
        const shared = secp256k1.getSharedSecret(skX.key, pkY.key, false)
        const dh = await crypto.subtle.digest('SHA-256', shared)
        return new Uint8Array(dh)
    }

    private async keyPairFromRawPrivateKey(rawPrivateKey: Uint8Array): Promise<CryptoKeyPair> {
        const privateKey = new XCryptoKey({
            algorithm: { name: ALGORITHM_NAME },
            key: rawPrivateKey,
            type: 'private',
        })
        const publicKey = await this.getPublicKeyFromPrivateKey(privateKey)
        return {
            privateKey,
            publicKey,
        }
    }
}
