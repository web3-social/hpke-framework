import { DhKemContext, XCryptoKey } from '@web3-social/hpke-framework';
import { HkdfBlake3Factory } from '@web3-social/hpke-hkdf-blake3';
import * as blake3 from '@web3-social/blake3-hkdf-js';
import * as secp256k1 from '@noble/secp256k1';
import * as consts from './consts.js';

export class Secp256k1Blake3Kem extends DhKemContext {
    constructor() {
        super({
            nSecret: consts.SECP256K1_DH_LENGTH,
            nPk: consts.SECP256K1_PUBLIC_KEY_LENGTH,
            nSk: consts.SECP256K1_PRIVATE_KEY_LENGTH,
            nDh: consts.SECP256K1_DH_LENGTH,
            kemId: consts.SECP256K1_BLAKE3_KEM_ID,
            kdfFactory: HkdfBlake3Factory,
        });
    }

    public async generateKeyPair(): Promise<CryptoKeyPair> {
        return this.keyPairFromRawPrivateKey(secp256k1.utils.randomPrivateKey());
    }
    public async deriveKeyPair(ikm: Uint8Array): Promise<CryptoKeyPair> {
        const hash = blake3.hkdf(consts.SECP256K1_PRIVATE_KEY_LENGTH + 16, ikm);
        return this.keyPairFromRawPrivateKey(secp256k1.utils.hashToPrivateKey(hash));
    }
    public async serializePublicKey(pkX: XCryptoKey): Promise<Uint8Array> {
        return pkX.key;
    }
    public async deserializePublicKey(pkXm: Uint8Array): Promise<XCryptoKey> {
        return new XCryptoKey({
            algorithm: { name: consts.ALGORITHM_NAME },
            key: pkXm,
            type: 'public',
        });
    }
    public async serializePrivateKey(skX: XCryptoKey): Promise<Uint8Array> {
        return skX.key;
    }
    public async deserializePrivateKey(skXm: Uint8Array): Promise<XCryptoKey> {
        return new XCryptoKey({
            algorithm: { name: consts.ALGORITHM_NAME },
            key: skXm,
            type: 'private',
        });
    }

    public async getPublicKeyFromPrivateKey(pkX: XCryptoKey): Promise<XCryptoKey> {
        const raw = secp256k1.getPublicKey(pkX.key, true);
        return new XCryptoKey({
            algorithm: { name: consts.ALGORITHM_NAME },
            key: raw,
            type: 'public',
        });
    }

    /**
     * Perform a non-interactive Diffie-Hellman exchange using the private key skX and public key pkY
     * to produce a Diffie-Hellman shared secret of length `nDh`.
     *
     * @param skX private key
     * @param pkY public key
     * @returns shared secret
     * @throws ValidationError
     */
    public async dh(skX: XCryptoKey, pkY: XCryptoKey): Promise<Uint8Array> {
        const shared = secp256k1.getSharedSecret(skX.key, pkY.key, false);
        return blake3.hash(shared);
    }

    private async keyPairFromRawPrivateKey(rawPrivateKey: Uint8Array): Promise<CryptoKeyPair> {
        const privateKey = new XCryptoKey({
            algorithm: { name: consts.ALGORITHM_NAME },
            key: rawPrivateKey,
            type: 'private',
        });
        const publicKey = await this.getPublicKeyFromPrivateKey(privateKey);
        return {
            privateKey,
            publicKey,
        };
    }
}
