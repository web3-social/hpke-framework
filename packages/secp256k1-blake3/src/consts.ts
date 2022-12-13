import { arrayFromAscii } from '@web3-social/hpke-framework'

export const ALGORITHM_NAME = 'secp256k1'
export const SECP256K1_PRIVATE_KEY_LENGTH = 32
export const SECP256K1_PUBLIC_KEY_LENGTH = 33
export const SECP256K1_BLAKE3_KEM_ID = 0x6b31
export const SECP256K1_DH_LENGTH = 32
export const SECP256K1_BLAKE3_DERIVE_INFO = arrayFromAscii('DHKEM(secp256k1, BLAKE3) deriveKey')
