import * as consts from './consts'
import { compress, wordsFromLittleEndianBytes } from './utils'
import { Output } from './output'

export class ChunkState {
    private chainingValue: Uint32Array
    public chunkCounterHi: number
    public chunkCounterLo: number
    private block: Uint8Array
    private blockLen: number
    private blocksCompressed: number
    private readonly flags: number

    constructor(keyWords: Uint32Array, chunkCounterHi: number, chunkCounterLo: number, flags: number) {
        this.chainingValue = keyWords
        this.chunkCounterHi = chunkCounterHi
        this.chunkCounterLo = chunkCounterLo
        this.block = new Uint8Array(consts.BLOCK_LEN)
        this.blockLen = 0
        this.blocksCompressed = 0
        this.flags = flags
    }

    length(): number {
        return consts.BLOCK_LEN * this.blocksCompressed + this.blockLen
    }

    startFlag(): number {
        if (this.blocksCompressed === 0) {
            return consts.CHUNK_START
        } else {
            return 0
        }
    }

    update(inputBytes: Uint8Array) {
        while (inputBytes.length !== 0) {
            if (this.blockLen === consts.BLOCK_LEN) {
                const blockWords = new Uint32Array(this.block.buffer, this.block.byteOffset, this.block.byteLength / 4)
                this.chainingValue = compress(
                    this.chainingValue,
                    blockWords,
                    this.chunkCounterHi,
                    this.chunkCounterLo,
                    consts.BLOCK_LEN,
                    this.flags | this.startFlag(),
                ).slice(0, 8)
                this.blocksCompressed += 1
                this.block = new Uint8Array(consts.BLOCK_LEN)
                this.blockLen = 0
            }

            const want = consts.BLOCK_LEN - this.blockLen
            const take = Math.min(want, inputBytes.length)
            this.block.set(inputBytes.slice(0, take), this.blockLen)
            this.blockLen += take
            inputBytes = inputBytes.slice(take)
        }
    }

    output(): Output {
        return new Output(
            this.chainingValue,
            wordsFromLittleEndianBytes(this.block),
            this.chunkCounterHi,
            this.chunkCounterLo,
            this.blockLen,
            this.flags | this.startFlag() | consts.CHUNK_END,
        )
    }
}
