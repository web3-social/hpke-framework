import { describe, expect, it } from 'vitest'
import testVector from './hmac_test_vector.json'
import { hmac } from '../src/hmac'

describe('HMAC', () => {
    testVector.case.forEach((vector) => {
        it(vector.description, () => {
            expect(
                Buffer.from(hmac(Buffer.from(vector.key, 'hex'), Buffer.from(vector.msg, 'hex'))).toString('hex'),
            ).toEqual(vector.hmac)
        })
    })
})
