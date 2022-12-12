# HKPE Framework

[HPKE](https://www.rfc-editor.org/rfc/rfc9180.html) stands for Hybrid Public Key Encryption.

### Warning

This project is experimental and all APIs are not stable.

**DO NOT** use in production.

### Suggestions

If you are going to use standard HPKE components, 
check [hpke-js](https://github.com/dajiaji/hpke-js) instead.

See [Standard HPKE Components Identifiers](#standard-hpke-components-identifiers) 
to check if standard components are enough for you.

## Backgrounds 

A HPKE cipher suite is a combination of:
- Key Derivation Function (HKDF)
- Key Encapsulation Mechanism (KEM)
- AEAD encryption algorithm

The framework provides abstraction for all subcomponents:
- `KdfContext` for general KDF
- `KemContext` for general KEM
  - `DhKemContext` for DH-Based KEM
- `AeadContext` for general AEAD algorithm

To create a HPKE cipher suite, just pass a valid combination:
```
new CipherSuite({
    kem: new YourKemImplementation(),
    kdfFactory: YourKdfFactory,
    aead: new YourAeadImplementation(),
}),
```

## Existing Implementations

### Standard

| KDF-ID |     KDF     |                  Package                  |
|:------:|:-----------:|:-----------------------------------------:|
| 0x0001 | HKDF-SHA256 | [@web3-social/hpke-hkdf](./packages/hkdf) |
| 0x0002 | HKDF-SHA384 | [@web3-social/hpke-hkdf](./packages/hkdf) |
| 0x0003 | HKDF-SHA512 | [@web3-social/hpke-hkdf](./packages/hkdf) |

| AEAD-ID |    AEAD     |                     Package                     |
|:-------:|:-----------:|:-----------------------------------------------:|
| 0x0001  | AES-128-GCM | [@web3-social/hpke-aes-gcm](./packages/aes-gcm) |
| 0x0002  | AES-256-GCM | [@web3-social/hpke-aes-gcm](./packages/aes-gcm) |

### Non-standard / Experimental

| KEM-ID |              KEM               |                            Package                             |
|:------:|:------------------------------:|:--------------------------------------------------------------:|
| 0x6b32 | DHKEM(secp256k1, HKDF-SHA-256) | [@web3-social/hpke-secp256k1-sha256](./packages/secp256k1-sha) |

### Broken

| KDF-ID |     KDF     |                         Package                         |
|:------:|:-----------:|:-------------------------------------------------------:|
|  N/A   | HKDF-BLAKE3 | [@web3-social/hpke-hkdf-blake3](./packages/hkdf-blake3) |

| KEM-ID |              KEM              |                              Package                              |
|:------:|:-----------------------------:|:-----------------------------------------------------------------:|
|  N/A   | DHKEM(secp256k1, HKDF-BLAKE3) | [@web3-social/hpke-secp256k1-blake3](./packages/secp256k1-blake3) |

| AEAD-ID |       AEAD       |                              Package                               |
|:-------:|:----------------:|:------------------------------------------------------------------:|
| 0x0003  | ChaCha20Poly1305 | [@web3-social/hpke-chacha20poly1305](./packages/chacha20-poly1305) |

### Standard HPKE Components Identifiers

#### KDF

| Value  |     KDF     | Nh  | Reference |
|:------:|:-----------:|:---:|:---------:|
| 0x0000 |  Reserved   | N/A | RFC 9180  |
| 0x0001 | HKDF-SHA256 | 32  | [RFC5869] |
| 0x0002 | HKDF-SHA384 | 48  | [RFC5869] |
| 0x0003 | HKDF-SHA512 | 64  | [RFC5869] |

#### KEM

| Value  |            KEM             | Nsecret | Nenc | Npk | Nsk | Auth |        Reference        |
|:------:|:--------------------------:|:-------:|:----:|:---:|:---:|:----:|:-----------------------:|
| 0x0000 |          Reserved          |   N/A   | N/A  | N/A | N/A | yes  |        RFC 9180         |
| 0x0010 | DHKEM(P-256, HKDF-SHA256)  |   32    |  65  | 65  | 32  | yes  | [NISTCurves], [RFC5869] |
| 0x0011 | DHKEM(P-384, HKDF-SHA384)  |   48    |  97  | 97  | 48  | yes  | [NISTCurves], [RFC5869] |
| 0x0012 | DHKEM(P-521, HKDF-SHA512)  |   64    | 133  | 133 | 66  | yes  | [NISTCurves], [RFC5869] |
| 0x0020 | DHKEM(X25519, HKDF-SHA256) |   32    |  32  | 32  | 32  | yes  |  [RFC5869], [RFC7748]   |
| 0x0021 |  DHKEM(X448, HKDF-SHA512)  |   64    |  56  | 56  | 56  | yes  |  [RFC5869], [RFC7748]   |

#### AEAD

| Value  |       AEAD       | Nk  | Nn  | Nt  | Reference |
|:------:|:----------------:|:---:|:---:|:---:|:---------:|
| 0x0000 |     Reserved     | N/A | N/A | N/A | RFC 9180  |
| 0x0001 |   AES-128-GCM    | 16  | 12  | 16  |   [GCM]   |
| 0x0002 |   AES-256-GCM    | 32  | 12  | 16  |   [GCM]   |
| 0x0003 | ChaCha20Poly1305 | 32  | 12  | 16  | [RFC8439] |
| 0xFFFF |   Export-only    | N/A | N/A | N/A | [RFC9180] |