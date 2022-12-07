import type { KemContext } from './kemContext.js';
import type { AeadContext } from './aeadContext.js';
import type { KdfContext, KdfFactory } from './kdfContext.js';
import { arrayFromAscii, i2osp, concatUint8Array } from './utils.js';
import { InvalidConfig, PskError } from './errors.js';
import { ReceiverContext, SenderContext } from './encryptionContext.js';
import type { EncryptionContextParams } from './encryptionContext.js';
import type { XCryptoKey } from './xCryptoKey.js';

export class HpkeMode {
    static Base = new HpkeMode(0x00);
    static Psk = new HpkeMode(0x01);
    static Auth = new HpkeMode(0x02);
    static AuthPsk = new HpkeMode(0x03);
    public readonly value: number;

    private constructor(value: number) {
        this.value = value;
    }
}

export interface SenderContextParams {
    mode: HpkeMode;
    pkR: XCryptoKey;
    info?: Uint8Array;
    psk?: Uint8Array;
    pskId?: Uint8Array;
    skS?: XCryptoKey;
}

export interface ReceiverContextParams {
    mode: HpkeMode;
    enc: Uint8Array;
    skR: XCryptoKey;
    info?: Uint8Array;
    psk?: Uint8Array;
    pskId?: Uint8Array;
    pkS?: XCryptoKey;
}

export interface KeyScheduleParams {
    mode: HpkeMode;
    sharedSecret: Uint8Array;
    info?: Uint8Array;
    psk?: Uint8Array;
    pskId?: Uint8Array;
}

export interface CipherSuiteParams {
    kem: KemContext;
    kdfFactory: KdfFactory;
    aead: AeadContext;
}
export class CipherSuite {
    public readonly kem: KemContext;
    public readonly kdf: KdfContext;
    public readonly aead: AeadContext;

    private readonly suiteId: Uint8Array;

    constructor({ kem, kdfFactory, aead }: CipherSuiteParams) {
        this.kem = kem;
        this.aead = aead;
        this.suiteId = concatUint8Array(
            arrayFromAscii('HPKE'),
            i2osp(kem.kemId, 2),
            i2osp(kdfFactory.kdfId, 2),
            i2osp(aead.aeadId, 2)
        );
        this.kdf = kdfFactory(this.suiteId);
    }

    public async createSenderContext({
        mode,
        pkR,
        info,
        psk,
        pskId,
        skS,
    }: SenderContextParams): Promise<{ enc: Uint8Array; ctx: SenderContext }> {
        const { sharedSecret, enc } =
            mode == HpkeMode.Base || mode == HpkeMode.Psk
                ? await this.kem.encap(pkR)
                : await this.kem.authEncap(
                      pkR,
                      skS ??
                          (() => {
                              throw new InvalidConfig();
                          })()
                  );

        if (mode == HpkeMode.Base || mode == HpkeMode.Auth) {
            psk = undefined;
            pskId = undefined;
        } else {
            if (psk == undefined || pskId == undefined) {
                throw new InvalidConfig();
            }
        }

        const params = await this.keySchedule({ mode, sharedSecret, info, psk, pskId });
        return {
            enc,
            ctx: new SenderContext(params),
        };
    }

    public async createReceiverContext({
        mode,
        enc,
        skR,
        info,
        psk,
        pskId,
        pkS,
    }: ReceiverContextParams): Promise<ReceiverContext> {
        const sharedSecret =
            mode == HpkeMode.Base || mode == HpkeMode.Psk
                ? await this.kem.decap(enc, skR)
                : await this.kem.authDecap(
                      enc,
                      skR,
                      pkS ??
                          (() => {
                              throw new InvalidConfig();
                          })()
                  );

        if (mode == HpkeMode.Base || mode == HpkeMode.Auth) {
            psk = undefined;
            pskId = undefined;
        } else {
            if (psk == undefined || pskId == undefined) {
                throw new InvalidConfig();
            }
        }
        const params = await this.keySchedule({ mode, sharedSecret, info, psk, pskId });
        return new ReceiverContext(params);
    }

    private verifyPskInputs(mode: HpkeMode, psk?: Uint8Array, pskId?: Uint8Array) {
        const gotPsk = psk !== undefined;
        const gotPskId = pskId !== undefined;
        if (gotPsk != gotPskId) {
            throw new PskError('Inconsistent PSK inputs');
        }
        if (gotPsk && (mode == HpkeMode.Base || mode == HpkeMode.Auth)) {
            throw new PskError('PSK input provided when not needed');
        }
        if (!gotPsk && (mode == HpkeMode.Psk || mode == HpkeMode.AuthPsk)) {
            throw new PskError('Missing required PSK input');
        }
    }

    private async keySchedule({
        mode,
        sharedSecret,
        info,
        psk,
        pskId,
    }: KeyScheduleParams): Promise<EncryptionContextParams> {
        this.verifyPskInputs(mode, psk, pskId);

        if (psk == undefined) psk = new Uint8Array();
        if (pskId == undefined) pskId = new Uint8Array();
        if (info == undefined) info = new Uint8Array();

        const pskIdHash = await this.kdf.labeledExtract(new Uint8Array(), arrayFromAscii('psk_id_hash'), pskId);
        const infoHash = await this.kdf.labeledExtract(arrayFromAscii(''), arrayFromAscii('info_hash'), info);
        const keyScheduleContext = concatUint8Array(new Uint8Array([mode.value]), pskIdHash, infoHash);

        const secret = await this.kdf.labeledExtract(sharedSecret, arrayFromAscii('secret'), psk);

        const key = await this.kdf.labeledExpand(secret, arrayFromAscii('key'), keyScheduleContext, this.aead.nK);
        const baseNonce = await this.kdf.labeledExpand(
            secret,
            arrayFromAscii('base_nonce'),
            keyScheduleContext,
            this.aead.nN
        );
        const exporterSecret = await this.kdf.labeledExpand(
            secret,
            arrayFromAscii('exp'),
            keyScheduleContext,
            this.kdf.nH
        );

        return {
            aead: this.aead,
            kdf: this.kdf,
            key,
            baseNonce,
            exporterSecret,
        };
    }
}
