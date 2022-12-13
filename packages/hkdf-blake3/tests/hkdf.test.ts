import { describe, expect, it } from 'vitest'
import testVector from './hkdf_test_vector.json'
import { HkdfBlake3Factory } from '../src'

describe('HKDF', () => {
    testVector.case.forEach((vector) => {
        it(vector.description, async () => {
            const hkdf = HkdfBlake3Factory(new Uint8Array())
            const prk = await hkdf.extract(Buffer.from(vector.salt, 'hex'), Buffer.from(vector.ikm, 'hex'))
            expect(Buffer.from(prk).toString('hex')).toEqual(vector.prk)
            const okm = await hkdf.expand(prk, Buffer.from(vector.info, 'hex'), vector.l)
            expect(Buffer.from(okm).toString('hex')).toEqual(vector.okm)
        })
    })
})
