import type { KemContext } from './kemContext'
import type { XCryptoKey } from './xCryptoKey'
import type { KdfContext, KdfFactory } from './kdfContext'
import { arrayFromAscii, i2osp, concatUint8Array } from './utils'

export interface DhKemContextParams {
    /** The length in bytes of a KEM shared secret produced by this KEM. */
    nSecret: number
    /** The length in bytes of an encoded public key for this KEM. */
    nPk: number
    /** The length in bytes of an encoded private key for this KEM. */
    nSk: number
    /** The length in bytes of a Diffie-Hellman shared secret produced by dh() */
    nDh: number
    /** 2 byte width kem identifier */
    kemId: number
    /** associated kdf factory */
    kdfFactory: KdfFactory
}

export abstract class DhKemContext implements KemContext {
    /** The length in bytes of a KEM shared secret produced by this KEM. */
    public readonly nSecret: number
    /** The length in bytes of an encapsulated key produced by this KEM. */
    public readonly nEnc: number
    /** The length in bytes of an encoded public key for this KEM. */
    public readonly nPk: number
    /** The length in bytes of an encoded private key for this KEM. */
    public readonly nSk: number

    /** The length in bytes of a Diffie-Hellman shared secret produced by dh() */
    public readonly nDh: number

    public readonly kemId: number

    public readonly kdf: KdfContext

    protected constructor({ nSecret, nPk, nSk, nDh, kemId, kdfFactory }: DhKemContextParams) {
        this.nSecret = nSecret
        this.nEnc = nPk
        this.nPk = nPk
        this.nSk = nSk
        this.nDh = nDh
        this.kemId = kemId
        this.kdf = kdfFactory(concatUint8Array(arrayFromAscii('KEM'), i2osp(kemId, 2)))
    }

    public abstract generateKeyPair(): Promise<CryptoKeyPair>
    public abstract deriveKeyPair(ikm: Uint8Array): Promise<CryptoKeyPair>
    public abstract serializePublicKey(pkX: XCryptoKey): Promise<Uint8Array>
    public abstract deserializePublicKey(pkXm: Uint8Array): Promise<XCryptoKey>
    public abstract serializePrivateKey(skX: XCryptoKey): Promise<Uint8Array>
    public abstract deserializePrivateKey(skXm: Uint8Array): Promise<XCryptoKey>

    public abstract getPublicKeyFromPrivateKey(pkX: XCryptoKey): Promise<XCryptoKey>

    /**
     * Perform a non-interactive Diffie-Hellman exchange using the private key skX and public key pkY
     * to produce a Diffie-Hellman shared secret of length `nDh`.
     *
     * @param skX private key
     * @param pkY public key
     * @returns shared secret
     * @throws ValidationError
     */
    public abstract dh(skX: XCryptoKey, pkY: XCryptoKey): Promise<Uint8Array>

    public async extractAndExpand(dh: Uint8Array, kemContext: Uint8Array): Promise<Uint8Array> {
        const eaePrk = await this.kdf.labeledExtract(arrayFromAscii(''), arrayFromAscii('eae_prk'), dh)
        return this.kdf.labeledExpand(eaePrk, arrayFromAscii('shared_secret'), kemContext, this.nSecret)
    }

    public async encap(pkR: XCryptoKey): Promise<{
        sharedSecret: Uint8Array
        enc: Uint8Array
    }> {
        const { privateKey: skE, publicKey: pkE } = await this.generateKeyPair()
        const dh = await this.dh(skE as XCryptoKey, pkR)
        const enc = await this.serializePublicKey(pkE as XCryptoKey)
        const pkRm = await this.serializePublicKey(pkR)
        const kemContext = concatUint8Array(enc, pkRm)
        const sharedSecret = await this.extractAndExpand(dh, kemContext)
        return {
            sharedSecret: sharedSecret,
            enc: enc,
        }
    }

    public async decap(enc: Uint8Array, skR: XCryptoKey): Promise<Uint8Array> {
        const pkE = await this.deserializePublicKey(enc)
        const dh = await this.dh(skR, pkE)
        const pkRm = await this.serializePrivateKey(await this.getPublicKeyFromPrivateKey(skR))
        const kemContext = concatUint8Array(enc, pkRm)
        return await this.extractAndExpand(dh, kemContext)
    }

    public async authEncap(
        pkR: XCryptoKey,
        skS: XCryptoKey,
    ): Promise<{
        sharedSecret: Uint8Array
        enc: Uint8Array
    }> {
        const { privateKey: skE, publicKey: pkE } = await this.generateKeyPair()
        const dh = concatUint8Array(await this.dh(skE as XCryptoKey, pkR), await this.dh(skS, pkE as XCryptoKey))
        const enc = await this.serializePublicKey(pkE as XCryptoKey)

        const pkRm = await this.serializePublicKey(pkR)
        const pkSm = await this.serializePublicKey(await this.getPublicKeyFromPrivateKey(skS))
        const kemContext = concatUint8Array(enc, pkRm, pkSm)
        const sharedSecret = await this.extractAndExpand(dh, kemContext)
        return {
            sharedSecret: sharedSecret,
            enc: enc,
        }
    }

    public async authDecap(enc: Uint8Array, skR: XCryptoKey, pkS: XCryptoKey): Promise<Uint8Array> {
        const pkE = await this.deserializePublicKey(enc)
        const dh = concatUint8Array(await this.dh(skR, pkE), await this.dh(skR, pkS))
        const pkRm = await this.serializePrivateKey(await this.getPublicKeyFromPrivateKey(skR))
        const pkSm = await this.serializePrivateKey(pkS)
        const kemContext = concatUint8Array(enc, pkRm, pkSm)
        return await this.extractAndExpand(dh, kemContext)
    }
}
