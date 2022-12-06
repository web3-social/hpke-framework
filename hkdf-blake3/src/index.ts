import {KdfContext, KdfFactory} from '@web3-social/hpke-framework';
import {extract, expand} from '@web3-social/blake3-hkdf-js';

const HKDF_BLAKE3_EXTRACT_SIZE = 32;
const HKDF_BLAKE3_ID = 0xff;
export const HkdfBlake3Factory: KdfFactory = (() => {
  const factory = ((suiteId: Uint8Array) => { return new HkdfBlake3Context(suiteId) as KdfContext; }) as KdfFactory;
  factory.kdfId = HKDF_BLAKE3_ID;
  return factory;
})();

export class HkdfBlake3Context extends KdfContext {

  constructor(suitId: Uint8Array) {
    super(HKDF_BLAKE3_EXTRACT_SIZE, 0xff, suitId);
  }

  public async extract(salt: Uint8Array, ikm: Uint8Array): Promise<Uint8Array> {
    return extract(salt, ikm);
  }

  public async expand(prk: Uint8Array, info: Uint8Array, l: number): Promise<Uint8Array> {
    return expand(prk, l, info);
  }

}