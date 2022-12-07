import { assert, describe, it } from 'vitest'
import {CipherSuite, HpkeMode, XCryptoKey} from "@web3-social/hpke-framework";
import {Secp256k1Blake3Kem} from "@web3-social/hpke-secp256k1-blake3";
import {HkdfBlake3Factory} from "@web3-social/hpke-hkdf-blake3";
import {Aes256GcmAead} from "@web3-social/hpke-aes-gcm";

describe('cipher suite', () => {
  it('basic', async () => {
    const cipherSuite = new CipherSuite({
      kem: new Secp256k1Blake3Kem(),
      kdfFactory: HkdfBlake3Factory,
      aead: new Aes256GcmAead(),
    });
  
    // const { privateKey: skS, publicKey: pkS } = await cipherSuite.kem.generateKeyPair();
    const { privateKey: skR, publicKey: pkR } = await cipherSuite.kem.generateKeyPair();
  
    const { enc, ctx: contextS} = await cipherSuite.createSenderContext({
      mode: HpkeMode.Base,
      pkR: pkR as XCryptoKey
    });
  
    const ct = await contextS.seal(new TextEncoder().encode('test message'));
  
    const contextR = await cipherSuite.createReceiverContext({
      mode: HpkeMode.Base,
      enc,
      skR: skR as XCryptoKey,
    });
  
    const pt = await contextR.open(ct);
    console.log(new TextDecoder().decode(pt));
  })
  
});
