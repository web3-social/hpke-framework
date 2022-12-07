export interface XCryptoKeyParams {
    algorithm: KeyAlgorithm
    key: Uint8Array
    type: KeyType
}

export class XCryptoKey implements CryptoKey {
    public readonly key: Uint8Array
    public readonly type: KeyType
    public readonly extractable: boolean = true
    public readonly algorithm: KeyAlgorithm
    public readonly usages: KeyUsage[] = ['deriveBits']

    constructor({ algorithm, key, type }: XCryptoKeyParams) {
        this.key = key
        this.type = type
        this.algorithm = algorithm
    }
}
