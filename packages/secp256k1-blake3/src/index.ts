import { arrayFromAscii, DhKemContext, getCrypto, XCryptoKey } from '@web3-social/hpke-framework';
import { HkdfBlake3Factory } from '@web3-social/hpke-hkdf-blake3';
import * as blake3 from '@web3-social/blake3-hkdf-js';
import * as secp256k1 from 'secp256k1';
import * as consts from './consts.js';

const crypto = getCrypto();

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
        const rawPrivateKey = new Uint8Array(consts.SECP256K1_PRIVATE_KEY_LENGTH);
        do {
            crypto.getRandomValues(rawPrivateKey);
        } while (!secp256k1.privateKeyVerify(rawPrivateKey));
        return this.keyPairFromRawPrivateKey(rawPrivateKey);
    }
    public async deriveKeyPair(ikm: Uint8Array): Promise<CryptoKeyPair> {
        let seq = 0;
        let rawPrivateKey;
        do {
            rawPrivateKey = blake3.hkdf(
                consts.SECP256K1_PRIVATE_KEY_LENGTH,
                ikm,
                undefined,
                arrayFromAscii('SECP256K1-DERIVED-KEY#' + seq)
            );
            seq += 1;
        } while (!secp256k1.privateKeyVerify(rawPrivateKey));
        return this.keyPairFromRawPrivateKey(rawPrivateKey);
    }
    public async serializePublicKey(pkX: XCryptoKey): Promise<Uint8Array> {
        return secp256k1.publicKeyConvert(pkX.key, true);
    }
    public async deserializePublicKey(pkXm: Uint8Array): Promise<XCryptoKey> {
        const raw = secp256k1.publicKeyConvert(pkXm, false);
        return new XCryptoKey({
            algorithm: { name: consts.ALGORITHM_NAME },
            key: raw,
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
        const raw = secp256k1.publicKeyCreate(pkX.key, false);
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
        const output = new Uint8Array(32);
        secp256k1.ecdh(
            pkY.key,
            skX.key,
            {
                data: new Uint8Array(64),
                hashfn: (x, y, data) => {
                    data.set(x);
                    data.set(y, 32);
                    return blake3.hash(data);
                },
            },
            output
        );
        return output;
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
