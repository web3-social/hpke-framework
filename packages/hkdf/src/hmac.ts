import { getCrypto } from '@web3-social/hpke-framework'

const crypto = getCrypto()

export async function hmac(key: CryptoKey, data: Uint8Array) {
    return new Uint8Array(await crypto.subtle.sign({ name: 'HMAC' }, key, data))
}
