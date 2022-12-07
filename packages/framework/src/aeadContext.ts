export interface AeadContext {
    /** The length in bytes of a key for this algorithm. */
    readonly nK: number
    /** The length in bytes of a nonce for this algorithm. */
    readonly nN: number
    /** The length in bytes of the authentication tag for this algorithm. */
    readonly nT: number
    readonly aeadId: number

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
    seal(key: Uint8Array, nonce: Uint8Array, pt: Uint8Array, aad?: Uint8Array): Promise<Uint8Array>

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
    open(key: Uint8Array, nonce: Uint8Array, ct: Uint8Array, aad?: Uint8Array): Promise<Uint8Array>
}
