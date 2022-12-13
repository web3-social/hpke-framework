import { describe, expect, it } from 'vitest'
import { Blake3 } from '../src/index'
import testVector from './test_vector.json'

// Each test is an input length and three outputs, one for each of the hash, keyed_hash, and derive_key modes.
// The input in each case is filled with a repeating sequence of 251 bytes: 0, 1, 2, ..., 249, 250, 0, 1, ..., and so on.
// The key used with keyed_hash is the 32-byte ASCII string \"whats the Elvish word for friend\", also given in the `key` field below.
// The context string used with derive_key is the ASCII string \"BLAKE3 2019-12-27 16:29:52 test vectors context\",
// also given in the `context_string` field below. Outputs are encoded as hexadecimal.
// Each case is an extended output, and implementations should also check that the first 32 bytes match their default-length output
describe(testVector.context_string, () => {
    const sequence = [...Array(251).keys()]
    const genPayload = (length: number) => {
        const n = Math.ceil(length / sequence.length)
        const repeated = new Array(n).fill(sequence).flat().slice(0, length)
        return new Uint8Array(repeated)
    }

    testVector.cases.forEach((vector) => {
        const hasher = Blake3.new()
        it(`hash input_len = ${vector.input_len}`, () => {
            const payload = genPayload(vector.input_len)
            hasher.update(payload)
            const expected = hasher.finalize(vector.hash.length / 2)
            expect(Buffer.from(expected).toString('hex')).toEqual(vector.hash)
            hasher.reset()
        })
    })

    testVector.cases.forEach((vector) => {
        const key = new TextEncoder().encode(testVector.key)
        const hasher = Blake3.newKeyed(key)
        it(`keyed_hash input_len = ${vector.input_len}`, () => {
            const payload = genPayload(vector.input_len)
            hasher.update(payload)
            const expected = hasher.finalize(vector.hash.length / 2)
            expect(Buffer.from(expected).toString('hex')).toEqual(vector.keyed_hash)
            hasher.reset()
        })
    })

    testVector.cases.forEach((vector) => {
        const hasher = Blake3.newDeriveKey(testVector.context_string)
        it(`derive_key input_len = ${vector.input_len}`, () => {
            const payload = genPayload(vector.input_len)
            hasher.update(payload)
            const expected = hasher.finalize(vector.hash.length / 2)
            expect(Buffer.from(expected).toString('hex')).toEqual(vector.derive_key)
            hasher.reset()
        })
    })
})
