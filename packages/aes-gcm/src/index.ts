import type { AeadContext } from '@web3-social/hpke-framework';
import { getCrypto } from '@web3-social/hpke-framework'

const crypto = getCrypto();

export class Aes256GcmAead implements AeadContext {
    /** The length in bytes of a key for this algorithm. */
    public readonly nK: number = 32;
    /** The length in bytes of a nonce for this algorithm. */
    public readonly nN: number = 12;
    /** The length in bytes of the authentication tag for this algorithm. */
    public readonly nT: number = 16;
    public readonly aeadId: number = 0x0002;

    /**
     * Encrypt and authenticate plaintext pt with associated data aad
     * using symmetric key and nonce, yielding ciphertext and tag ct.
     *
     * @param key symmetric key
     * @param nonce nonce
     * @param aad associated data
     * @param pt plaintext
     * @returns ct ciphertext and tag
     * @throws MessageLimitReachedError
     */
    public async seal(key: Uint8Array, nonce: Uint8Array, pt: Uint8Array, aad?: Uint8Array): Promise<Uint8Array> {
        const importKey = await crypto.subtle.importKey('raw', key, 'AES-GCM', false, ['encrypt']);
        const alg = {
            name: 'AES-GCM',
            iv: nonce,
            additionalData: aad
        }
        const ct = await crypto.subtle.encrypt(alg, importKey, pt);
        return new Uint8Array(ct);
    }

    /**
     * Decrypt ciphertext and tag ct using associated data aad
     * with symmetric key and nonce, returning plaintext message pt.
     *
     * @param key symmetric key
     * @param nonce nonce
     * @param aad associated data
     * @param ct ciphertext and tag
     * @returns plaintext message
     * @throws OpenError
     * @throws MessageLimitReachedError
     */
    public async open(key: Uint8Array, nonce: Uint8Array, ct: Uint8Array, aad?: Uint8Array): Promise<Uint8Array> {
        const importKey = await crypto.subtle.importKey('raw', key, 'AES-GCM', false, ['decrypt']);
        const alg = {
            name: 'AES-GCM',
            iv: nonce,
            additionalData: aad
        };
        const pt = await crypto.subtle.decrypt(alg, importKey, ct);
        return new Uint8Array(pt);
    }
}