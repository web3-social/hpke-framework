import { AeadContext } from '@web3-social/hpke-framework';
import { chacha20poly1305_seal, chacha20poly1305_open, xchacha20poly1305_seal, xchacha20poly1305_open } from '@web3-social/chacha20-poly1305-js-sys';
export class Chacha20Ploy1305Aead implements AeadContext {
    /** The length in bytes of a key for this algorithm. */
    public readonly nK: number = 32;
    /** The length in bytes of a nonce for this algorithm. */
    public readonly nN: number = 12;
    /** The length in bytes of the authentication tag for this algorithm. */
    public readonly nT: number = 16;
    public readonly aeadId: number = 0xff;

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
        return chacha20poly1305_seal(key, nonce, aad ?? new Uint8Array(), pt);
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
        return chacha20poly1305_open(key, nonce, aad ?? new Uint8Array(), ct);
    }
}

export class XChacha20Ploy1305Aead implements AeadContext {
    /** The length in bytes of a key for this algorithm. */
    public readonly nK: number = 32;
    /** The length in bytes of a nonce for this algorithm. */
    public readonly nN: number = 24;
    /** The length in bytes of the authentication tag for this algorithm. */
    public readonly nT: number = 16;
    public readonly aeadId: number = 0xff;

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
        return xchacha20poly1305_seal(key, nonce, aad ?? new Uint8Array(), pt);
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
        return xchacha20poly1305_open(key, nonce, aad ?? new Uint8Array(), ct);
    }
}
