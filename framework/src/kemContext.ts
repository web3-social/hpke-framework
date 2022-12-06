import { XCryptoKey } from './xCryptoKey';

export interface KemContext {
    /** The length in bytes of a KEM shared secret produced by this KEM. */
    readonly nSecret: number;
    /** The length in bytes of an encapsulated key produced by this KEM. */
    readonly nEnc: number;
    /** The length in bytes of an encoded public key for this KEM. */
    readonly nPk: number;
    /** The length in bytes of an encoded private key for this KEM. */
    readonly nSk: number;
    readonly kemId: number;

    /**
     * Randomized algorithm to generate a key pair (skX, pkX)
     *
     * @returns key pair
     */
    generateKeyPair(): Promise<CryptoKeyPair>;

    /**
     * Deterministic algorithm to derive a key pair (skX, pkX) from the byte string ikm.
     * ikm **SHOULD** have at least `nSk` bytes of entropy.
     *
     * @param ikm
     * @returns key pair
     */
    deriveKeyPair(ikm: Uint8Array): Promise<CryptoKeyPair>;

    /**
     * Produce a byte string of length `nPk` encoding the public key pkX.
     *
     * @param pkX public key
     * @returns public key in byte string
     */
    serializePublicKey(pkX: XCryptoKey): Promise<Uint8Array>;

    /**
     * Parse a byte string of length `nPk` to recover a public key.
     *
     * @param pkXm public key in byte string
     * @returns XCryptoKey
     * @throws DeserializeError
     */
    deserializePublicKey(pkXm: Uint8Array): Promise<XCryptoKey>;

    /**
     * Produce a byte string of length Nsk encoding the private key skX.
     * This is optional for an implementation.
     *
     * @param skX
     * @returns private key in byte string
     * @throws UnsupportedError
     */
    serializePrivateKey(skX: XCryptoKey): Promise<Uint8Array>;

    /**
     * Parse a byte string of length Nsk to recover a private key.
     * This is optional for an implementation.
     *
     * @param skXm private key in byte string
     * @returns XCryptoKey
     * @throws DeserializeError
     * @throws UnsupportedError
     */
    deserializePrivateKey(skXm: Uint8Array): Promise<XCryptoKey>;

    /**
     * Retrieve public key from private key
     *
     * @param pkX public key
     * @returns XCryptoKey
     */
    getPublicKeyFromPrivateKey(pkX: XCryptoKey): Promise<XCryptoKey>;

    /**
     * Randomized algorithm to generate an ephemeral, fixed-length symmetric key (the KEM shared secret)
     * and a fixed-length encapsulation of that key that can be decapsulated
     * by the holder of the private key corresponding to pkR.
     *
     * @param pkR recipient public key
     * @returns shared secret and encapsulated representation of shared secret
     * @throws EncapError
     */
    encap(pkR: XCryptoKey): Promise<{ sharedSecret: Uint8Array; enc: Uint8Array }>;

    /**
     * Deterministic algorithm using the private key skR to recover
     * the ephemeral symmetric key (the KEM shared secret) from its encapsulated representation enc.
     *
     * @param enc encapsulated representation of shared secret
     * @param skR recipient secret key
     * @returns shared secret
     * @throws DecapError
     */
    decap(enc: Uint8Array, skR: XCryptoKey): Promise<Uint8Array>;

    /**
     * Same as Encap(), and the outputs encode an assurance that the KEM shared secret was generated
     * by the holder of the private key skS.
     * This is optional for an implementation.
     *
     * @param pkR recipient public key
     * @param skS sender private key
     * @returns shared secret and encapsulated representation of shared secret
     * @throws UnsupportedError
     */
    authEncap(pkR: XCryptoKey, skS: XCryptoKey): Promise<{ sharedSecret: Uint8Array; enc: Uint8Array }>;

    /**
     * Same as Decap(), and the recipient is assured that the KEM shared secret was generated
     * by the holder of the private key skS.
     * This is optional for an implementation.
     *
     * @param enc encapsulated representation of shared secret
     * @param skR recipient secret key
     * @param pkS sender private key
     * @returns shared secret
     * @throws DecapError
     * @throws UnsupportedError
     */
    authDecap(enc: Uint8Array, skR: XCryptoKey, pkS: XCryptoKey): Promise<Uint8Array>;
}
