import { Buffer } from 'buffer';
import { Crypto } from '@peculiar/webcrypto';
import crypto from 'crypto';

import { cborDecode, cborEncode } from './cbor';
import {
  CosePayload,
  CoseProtectedHeaders,
  CoseSignature,
  CoseUnprotectedHeaders,
  Header,
} from './cose';
import { extractAlgorithm } from './headers';

const COSE_ALGS = new Map<number, { name: string, hash: string, curve: string }>([
  [-7, { name: 'ECDSA', hash: 'sha-256', curve: 'P-256' }], // ES256
  [-35, { name: 'ECDSA', hash: 'sha-384', curve: 'P-384' }], // ES384
  [-36, { name: 'ECDSA', hash: 'sha-512', curve: 'P-521' }], // ES512
]);

/**
 * A COSE_Sign1 structure (https://datatracker.ietf.org/doc/html/rfc8152#section-4.2)
 *
 */
export default class CoseSign1 {
  public readonly protectedHeaders: CoseProtectedHeaders;
  public readonly unprotectedHeaders: CoseUnprotectedHeaders;
  public readonly payload: CosePayload;
  public readonly signature: CoseSignature;

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

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  getDecodedPayload(): any {
    return cborDecode(this.payload);
  }

  public get decodedProtectedHeaders(): Map<Header, Buffer | number | string> {
    const decoded = cborDecode(this.protectedHeaders, { mapsAsObjects: false });
    // @ts-ignore
    return Array.from(decoded).reduce((acc, [key, value]) => {
      if (key == Header.kid) {
        value = new TextDecoder().decode(value);
      }
      // @ts-ignore
      acc.set(key, value);
      return acc;
    }, new Map());
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

    const crypto = new Crypto();

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
