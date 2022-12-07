import type { AeadContext } from './aeadContext.js'
import { arrayFromAscii, i2osp, xor } from './utils.js'
import { MessageLimitReachedError } from './errors.js'
import type { KdfContext } from './kdfContext.js'

export interface EncryptionContextParams {
    aead: AeadContext
    kdf: KdfContext
    key: Uint8Array
    baseNonce: Uint8Array
    exporterSecret: Uint8Array
    seq?: number
}

class EncryptionContext {
    aead: AeadContext
    kdf: KdfContext
    key: Uint8Array
    baseNonce: Uint8Array
    exporterSecret: Uint8Array
    seq: number

    constructor({ aead, kdf, key, baseNonce, exporterSecret, seq }: EncryptionContextParams) {
        this.aead = aead
        this.kdf = kdf
        this.key = key
        this.baseNonce = baseNonce
        this.exporterSecret = exporterSecret
        this.seq = seq ?? 0
    }

    protected computeNonce(): Uint8Array {
        const seqBytes = i2osp(this.seq, this.aead.nN)
        return xor(this.baseNonce, seqBytes)
    }

    protected incrementSeq() {
        if (this.seq >= (1 << (8 * this.aead.nN)) - 1) {
            throw new MessageLimitReachedError()
        }
        this.seq += 1
    }

    /**
     * HPKE provides an interface for exporting secrets from the encryption context using
     * a variable-length pseudorandom function (PRF),
     * similar to the TLS 1.3 exporter interface (see [RFC8446], Section 7.5).
     *
     * interface takes as input a context string exporter_context and
     * a desired length L in bytes, and produces a secret derived from
     * the internal exporter secret using the corresponding KDF Expand function.
     *
     * @param exporterContext
     * @param l
     */
    public export(exporterContext: Uint8Array, l: number) {
        return this.kdf.labeledExpand(this.exporterSecret, arrayFromAscii('sec'), exporterContext, l)
    }
}
export class SenderContext extends EncryptionContext {
    constructor(params: EncryptionContextParams) {
        super({ ...params, seq: 0 })
    }

    public async seal(pt: Uint8Array, aad?: Uint8Array) {
        const ct = await this.aead.seal(this.key, this.computeNonce(), pt, aad)
        this.incrementSeq()
        return ct
    }
}

export class ReceiverContext extends EncryptionContext {
    constructor(params: EncryptionContextParams) {
        super({ ...params, seq: 0 })
    }

    public async open(ct: Uint8Array, aad?: Uint8Array) {
        const pt = await this.aead.open(this.key, this.computeNonce(), ct, aad)
        this.incrementSeq()
        return pt
    }
}
