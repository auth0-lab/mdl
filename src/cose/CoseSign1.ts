import { Buffer } from 'buffer';
import crypto from 'crypto';

import { cborDecode, cborEncode } from './cbor';
import {
  CosePayload,
  CoseProtectedHeaders,
  CoseSignature,
  CoseUnprotectedHeaders,
  Header,
} from './cose';
import { DataItem } from './DataItem';
import { ValidityInfo } from '../deviceResponse/types';

const COSE_ALGS = new Map<number, { name: string, hash: string, curve: string }>([
  [-7, { name: 'ECDSA', hash: 'sha-256', curve: 'P-256' }], // ES256
  [-35, { name: 'ECDSA', hash: 'sha-384', curve: 'P-384' }], // ES384
  [-36, { name: 'ECDSA', hash: 'sha-512', curve: 'P-521' }], // ES512
]);

type Payload = {
  digestAlgorithm: string;
  docType: string;
  version: string;

  valueDigests: Map<string, Map<number, Buffer>>;

  validityInfo: ValidityInfo;

  validityDigests: {
    [key: string]: Map<number, Buffer>;
  };

  deviceKeyInfo?: {
    [key: string]: any;
    deviceKey: Map<number, Buffer | number>;
  };
};

/**
 * A COSE_Sign1 structure (https://datatracker.ietf.org/doc/html/rfc8152#section-4.2)
 *
 */
export default class CoseSign1 {
  public readonly protectedHeaders: CoseProtectedHeaders;
  public readonly unprotectedHeaders: CoseUnprotectedHeaders;
  public readonly payload: CosePayload;
  public readonly signature: CoseSignature;
  #decodedPayload: Payload;

  constructor([
    protectedHeaders,
    unprotectedHeaders,
    payload,
    signature,
  ]: Array<unknown>) {
    this.protectedHeaders = protectedHeaders as CoseProtectedHeaders;
    this.unprotectedHeaders = unprotectedHeaders as CoseUnprotectedHeaders;
    this.payload = payload as CosePayload;
    this.signature = signature as CoseSignature;
  }

  public get decodedProtectedHeaders(): Map<Header, Buffer | number | string> {
    const decoded = cborDecode(this.protectedHeaders, { mapsAsObjects: false });
    return Array.from(decoded).reduce((acc, [key, value]) => {
      let v = value;
      // eslint-disable-next-line eqeqeq
      if (key == Header.kid) {
        v = new TextDecoder().decode(value);
      }
      // @ts-ignore
      acc.set(key, v);
      return acc;
    }, new Map()) as Map<Header, Buffer | number | string>;
  }

  public get decodedPayload(): Payload {
    if (this.#decodedPayload) { return this.#decodedPayload; }
    let decoded = cborDecode(this.payload);
    decoded = decoded instanceof DataItem ? decoded.data : decoded;
    decoded = Object.fromEntries(decoded);
    const mapValidityInfo = (validityInfo: Map<string, Buffer>) => {
      if (!validityInfo) { return validityInfo; }
      return Object.fromEntries([...validityInfo.entries()].map(([key, value]) => {
        return [key, Buffer.isBuffer(value) ? cborDecode(value) : value];
      }));
    };
    const result: Payload = {
      ...decoded,
      validityInfo: mapValidityInfo(decoded.validityInfo),
      validityDigests: decoded.validityDigests ? Object.fromEntries(decoded.validityDigests) : decoded.validityDigests,
      deviceKeyInfo: decoded.deviceKeyInfo ? Object.fromEntries(decoded.deviceKeyInfo) : decoded.deviceKeyInfo,
    };
    this.#decodedPayload = result;
    return result;
  }

  async verify(publicKey: ArrayBuffer | crypto.webcrypto.JsonWebKey, options: { publicKeyFormat: 'spki' | 'raw' | 'jwk', detachedContent?: Buffer }) {
    // https://datatracker.ietf.org/doc/html/rfc8152#section-4.4
    const ToBeSigned = cborEncode([
      'Signature1',
      this.protectedHeaders,
      Buffer.alloc(0),
      this.payload && this.payload.length > 0 ? this.payload : options.detachedContent,
    ]);

    const algNumber = this.decodedProtectedHeaders.get(Header.algorithm) as number;
    const algInfo = COSE_ALGS.get(algNumber);

    if (!algInfo) {
      throw new Error(`Unsupported COSE alg: ${algNumber} `);
    }

    const pk = await crypto.subtle.importKey(
      // @ts-ignore
      options.publicKeyFormat,
      publicKey,
      { name: algInfo.name, namedCurve: algInfo.curve },
      true,
      ['verify'],
    );

    return crypto.subtle.verify(
      { name: algInfo.name, hash: algInfo.hash },
      pk,
      this.signature,
      ToBeSigned,
    );
  }
}
