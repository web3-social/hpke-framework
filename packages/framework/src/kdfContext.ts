import { arrayFromAscii, i2osp, concatUint8Array } from './utils.js'

export interface KdfFactory {
    kdfId: number
    (suiteId: Uint8Array): KdfContext
}

export abstract class KdfContext {
    /** The output size of the extract() function in bytes. */
    public readonly nH: number
    public readonly kdfId: number
    /**
     * The value of suite_id depends on where the KDF is used;
     * it is assumed implicit from the implementation and not passed as a parameter.
     * If used inside a KEM algorithm, suite_id MUST start with "KEM" and identify this KEM algorithm;
     * if used in the remainder of HPKE, it MUST start with "HPKE" and identify the entire ciphersuite in use.
     */
    public readonly suiteId: Uint8Array

    protected constructor(nH: number, kdfId: number, suiteId: Uint8Array) {
        this.nH = nH
        this.kdfId = kdfId
        this.suiteId = suiteId
    }

    /**
     * Extract a pseudorandom key of fixed length `nH` bytes from ikm and an optional salt.
     *
     * @param salt byte string salt
     * @param ikm input keying material
     * @returns pseudorandom key
     */
    public abstract extract(salt: Uint8Array, ikm: Uint8Array): Promise<Uint8Array>

    /**
     * Expand a pseudorandom key prk using optional string info into L bytes of output keying material.
     *
     * @param prk pseudorandom key
     * @param info platform and application specific info
     * @param l output length
     * @returns output keying material
     */
    public abstract expand(prk: Uint8Array, info: Uint8Array, l: number): Promise<Uint8Array>

    public labeledExtract(salt: Uint8Array, label: Uint8Array, ikm: Uint8Array): Promise<Uint8Array> {
        const labeledIkm = concatUint8Array(arrayFromAscii('HPKE-v1'), this.suiteId, label, ikm)
        return this.extract(salt, labeledIkm)
    }

    public labeledExpand(prk: Uint8Array, label: Uint8Array, info: Uint8Array, l: number): Promise<Uint8Array> {
        const labeledInfo = concatUint8Array(i2osp(l, 2), arrayFromAscii('HPKE-v1'), this.suiteId, label, info)
        return this.expand(prk, labeledInfo, l)
    }
}
