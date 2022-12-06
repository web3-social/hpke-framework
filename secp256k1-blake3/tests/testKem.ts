import { Secp256k1Blake3Kem } from '../src';
import { describe } from 'mocha';
import { assert } from 'chai';
import * as consts from '../src/consts';
import { arrayFromHex, XCryptoKey } from '@web3-social/hpke-framework';

describe('DHKEM(secp256k1, BLAKE3)', () => {
    it('key length', async () => {
        const kem = new Secp256k1Blake3Kem();
        const { privateKey: sk, publicKey: pk } = await kem.generateKeyPair();
        assert.equal((sk as XCryptoKey).key.length, consts.SECP256K1_PRIVATE_KEY_LENGTH);
        const pkm = await kem.serializePublicKey(pk as XCryptoKey);
        assert.equal(pkm.length, consts.SECP256K1_PUBLIC_KEY_LENGTH);
    });
    it('dh same and length', async () => {
        const kem = new Secp256k1Blake3Kem();
        const { privateKey: sk1, publicKey: pk1 } = await kem.generateKeyPair();
        const { privateKey: sk2, publicKey: pk2 } = await kem.generateKeyPair();
        const dh1 = await kem.dh(sk1 as XCryptoKey, pk2 as XCryptoKey);
        assert.equal(dh1.length, consts.SECP256K1_DH_LENGTH);
        const dh2 = await kem.dh(sk2 as XCryptoKey, pk1 as XCryptoKey);
        assert.equal(Buffer.from(dh1).toString('hex'), Buffer.from(dh2).toString('hex'));
    });
    it('derive is deterministic', async () => {
        const kem = new Secp256k1Blake3Kem();
        const ikm = arrayFromHex('0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b');
        const { privateKey: sk1, publicKey: pk1 } = await kem.deriveKeyPair(ikm);
        const { privateKey: sk2, publicKey: pk2 } = await kem.deriveKeyPair(ikm);
        assert.equal(
            Buffer.from((sk1 as XCryptoKey).key).toString('hex'),
            Buffer.from((sk2 as XCryptoKey).key).toString('hex')
        );
        assert.equal(
            Buffer.from((pk1 as XCryptoKey).key).toString('hex'),
            Buffer.from((pk2 as XCryptoKey).key).toString('hex')
        );
    });
});
