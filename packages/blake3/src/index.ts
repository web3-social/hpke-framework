import * as consts from './consts'
import { wordsFromLittleEndianBytes } from './utils'
import { Output } from './output'
import { ChunkState } from './chunkState'

const Encoder = new TextEncoder()

function parentOutput(
    leftChildCv: Uint32Array,
    rightChildCv: Uint32Array,
    keyWords: Uint32Array,
    flags: number,
): Output {
    const blockWords = new Uint32Array(16)
    blockWords.set(leftChildCv)
    blockWords.set(rightChildCv, 8)

    return new Output(keyWords, blockWords, 0, 0, consts.BLOCK_LEN, consts.PARENT | flags)
}

function parentCv(
    leftChildCv: Uint32Array,
    rightChildCv: Uint32Array,
    keyWords: Uint32Array,
    flags: number,
): Uint32Array {
    return parentOutput(leftChildCv, rightChildCv, keyWords, flags).chainingValue()
}

export class Blake3 {
    public static readonly KEY_LEN = consts.KEY_LEN
    public static readonly BLOCK_LEN = consts.BLOCK_LEN
    public static readonly OUT_LEN = consts.OUT_LEN

    private chunkState: ChunkState
    private readonly keyWords: Uint32Array
    private readonly cvStack: Uint32Array[] = new Array(54)
    private cvStackLength: number = 0
    private readonly flags: number

    private static hasher = new Blake3()
    private static contextHasher = new Blake3(consts.IV, consts.DERIVE_KEY_CONTEXT)

    private constructor(keyWords?: Uint32Array, flags?: number) {
        if (keyWords === undefined) {
            keyWords = consts.IV
        }
        if (keyWords.length !== 8) {
            throw new Error('keyWords must be 8 bytes')
        }
        if (flags === undefined) {
            flags = 0
        }
        this.chunkState = new ChunkState(keyWords, 0, 0, flags)
        this.keyWords = keyWords
        this.flags = flags
    }

    public static new(): Blake3 {
        return new Blake3()
    }

    public static newKeyed(key: Uint32Array | Uint8Array): Blake3 {
        if (key instanceof Uint8Array) {
            key = wordsFromLittleEndianBytes(key)
        }
        return new Blake3(key, consts.KEYED_HASH)
    }

    public static newDeriveKey(context: string): Blake3 {
        const contextBytes = Encoder.encode(context)
        Blake3.contextHasher.update(contextBytes)
        const key = Blake3.contextHasher.finalize(consts.KEY_LEN)
        Blake3.contextHasher.reset()
        const keyWords = wordsFromLittleEndianBytes(key)
        return new Blake3(keyWords, consts.DERIVE_KEY_MATERIAL)
    }

    /**
     * one shot API
     * @param input
     * @param length
     */
    public static hash(input: Uint8Array | string, length: number = consts.OUT_LEN): Uint8Array {
        if (typeof input === 'string') {
            input = Encoder.encode(input)
        }
        Blake3.hasher.update(input)
        const digest = Blake3.hasher.finalize(length)
        Blake3.hasher.reset()
        return digest
    }

    private pushStack(cv: Uint32Array) {
        this.cvStack[this.cvStackLength] = cv
        this.cvStackLength += 1
    }

    private pop_stack(): Uint32Array {
        this.cvStackLength -= 1
        return this.cvStack[this.cvStackLength]!
    }

    private addChunkChainingValue(newCv: Uint32Array, totalChunksHi: number, totalChunksLo: number) {
        while ((totalChunksLo & 1) === 0) {
            newCv = parentCv(this.pop_stack(), newCv, this.keyWords, this.flags)
            totalChunksLo = (totalChunksLo >>> 1) | (totalChunksHi << 31)
            totalChunksHi >>>= 1
        }
        this.pushStack(newCv)
    }

    public update(inputBytes: Uint8Array) {
        while (inputBytes.length !== 0) {
            if (this.chunkState.length() === consts.CHUNK_LEN) {
                const chunkCv = this.chunkState.output().chainingValue()
                const totalChunksLo = this.chunkState.chunkCounterLo + 1
                const totalChunksHi = (this.chunkState.chunkCounterHi + (totalChunksLo >> 16)) >> 16
                this.addChunkChainingValue(chunkCv, totalChunksHi!, totalChunksLo!)
                this.chunkState = new ChunkState(this.keyWords, totalChunksHi!, totalChunksLo!, this.flags)
            }
            const want = consts.CHUNK_LEN - this.chunkState.length()
            const take = Math.min(want, inputBytes.length)
            this.chunkState.update(inputBytes.slice(0, take))
            inputBytes = inputBytes.slice(take)
        }
    }

    public finalize(length: number = consts.OUT_LEN): Uint8Array {
        let output = this.chunkState.output()
        let parentNodesRemaining = this.cvStackLength
        while (parentNodesRemaining > 0) {
            parentNodesRemaining -= 1
            output = parentOutput(
                this.cvStack[parentNodesRemaining]!,
                output.chainingValue(),
                this.keyWords,
                this.flags,
            )
        }
        return output.rootOutputBytes(length)
    }

    public reset() {
        this.chunkState = new ChunkState(this.keyWords, 0, 0, this.flags)
        this.cvStackLength = 0
    }
}
