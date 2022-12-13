import { describe, bench } from 'vitest'
import { Blake3 } from '../src'
import { createHash, randomBytes } from 'crypto'

;[
    { size: '64B', data: new Uint8Array(64), rounds: 10000 },
    { size: '64KB', data: new Uint8Array(1024 * 64), rounds: 1000 },
    //{ size: '64MB', data: new Uint8Array(1024 * 1024 * 64), rounds: 10 },
].forEach(({ size, data, rounds }) => {
    describe(`size = ${size}`, () => {
        bench(
            `BLAKE3`,
            () => {
                const hasher = new Blake3()
                hasher.update(data)
                hasher.finalize()
            },
            {
                iterations: rounds,
            },
        )
        ;['md5', 'sha1', 'sha256', 'sha512'].map((alg) =>
            bench(alg.toUpperCase(), () => createHash(alg).update(data).digest(), {
                iterations: rounds,
            }),
        )
    })
})
