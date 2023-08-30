import crypto from 'crypto';
import { cborEncode } from './cbor';
import {
  CosePayload,
  CoseProtectedHeaders,
  CoseTag,
  CoseUnprotectedHeaders,
  Header,
  CoseMacAlgorithm,
} from './cose';
import { extractAlgorithm } from './headers';
import { hmacSHA256 } from '../deviceResponse/utils';

/**
 * A COSE_Mac0 structure (https://datatracker.ietf.org/doc/html/rfc8152#section-6.2)
 *
 */
export default class CoseMac0 {
  public readonly protectedHeaders: CoseProtectedHeaders;
  public readonly unprotectedHeaders: CoseUnprotectedHeaders;
  public readonly payload: CosePayload;
  public readonly tag: CoseTag;

  constructor([
    protectedHeaders,
    unprotectedHeaders,
    payload,
    tag,
  ]: Array<unknown>) {
    this.protectedHeaders = protectedHeaders as CoseProtectedHeaders;
    this.unprotectedHeaders = unprotectedHeaders as CoseUnprotectedHeaders;
    this.payload = payload as CosePayload;
    this.tag = tag as CoseTag;
  }

  static async generate(
    key: Buffer | ArrayBuffer,
    payload: Buffer,
    detachedContent?: Buffer,
  ): Promise<CoseMac0> {
    const encodedProtectedHeaders = cborEncode(
      new Map([[Header.algorithm, CoseMacAlgorithm.HMAC_256_256]]),
    );

    const macStructure = [
      'MAC0', // context
      encodedProtectedHeaders, // protected
      Buffer.alloc(0), // externalAAD,
      payload.length > 0 ? payload : detachedContent, // payload
    ];

    const hmac = Buffer.from(await hmacSHA256(key, cborEncode(macStructure)));

    return new CoseMac0([
      encodedProtectedHeaders,
      [],
      payload.length > 0 ? payload : null,
      hmac,
    ]);
  }

  hasSupportedAlg() {
    const algNumber = extractAlgorithm(this);
    return algNumber === CoseMacAlgorithm.HMAC_256_256;
  }
}
