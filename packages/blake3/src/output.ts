import { compress } from './utils'
import * as consts from './consts'

export class Output {
    private readonly inputChainingValue: Uint32Array
    private readonly blockWords: Uint32Array
    private readonly counterHi: number
    private readonly counterLo: number
    private readonly blockLen: number
    private readonly flags: number

    constructor(
        inputChainingValue: Uint32Array,
        blockWords: Uint32Array,
        counterHi: number,
        counterLo: number,
        blockLen: number,
        flags: number,
    ) {
        this.inputChainingValue = inputChainingValue
        this.blockWords = blockWords
        this.counterHi = counterHi
        this.counterLo = counterLo
        this.blockLen = blockLen
        this.flags = flags
    }

    chainingValue(): Uint32Array {
        return compress(
            this.inputChainingValue,
            this.blockWords,
            this.counterHi,
            this.counterLo,
            this.blockLen,
            this.flags,
        ).slice(0, 8)
    }

    rootOutputBytes(length: number): Uint8Array {
        const outputBytes = new Uint8Array(length)
        let i = 0
        while (i < length) {
            const words = compress(
                this.inputChainingValue,
                this.blockWords,
                0,
                Math.floor(i / consts.BLOCK_LEN),
                this.blockLen,
                this.flags | consts.ROOT,
            )
            // assume browser is little endian
            const bytes = new Uint8Array(words.buffer, words.byteOffset, words.byteLength)
            const take = Math.min(bytes.length, length - i)
            outputBytes.set(bytes.slice(0, take), i)
            i += take
        }
        return outputBytes
    }
}
