import crypto from 'node:crypto';
import { CoseMacAlgorithm } from './algorithms';
import { cborEncode } from './cbor';
import {
  CosePayload,
  CoseProtectedHeaders,
  CoseTag,
  CoseUnprotectedHeaders,
} from './cose';
import Header from './header';

/**
 * A COSE_Mac0 structure (https://datatracker.ietf.org/doc/html/rfc8152#section-6.2)
 *
 */
export default class CoseMac0 {
  private protectedHeaders: CoseProtectedHeaders;

  private unprotectedHeaders: CoseUnprotectedHeaders;

  private payload: CosePayload;

  private tag: CoseTag;

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
    key: Buffer,
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

    const hmac = crypto
      .createHmac('SHA-256', key)
      .update(cborEncode(macStructure))
      .digest();
    return new CoseMac0([
      encodedProtectedHeaders,
      [],
      payload.length > 0 ? payload : null,
      hmac,
    ]);
  }

  /* Getters and setters */
  getUnprotectedHeaders(): CoseUnprotectedHeaders {
    return this.unprotectedHeaders;
  }

  setUnprotectedHeaders(unprotectedHeaders: CoseUnprotectedHeaders) {
    this.unprotectedHeaders = unprotectedHeaders;
  }

  getProtectedHeaders(): CoseProtectedHeaders {
    return this.protectedHeaders;
  }

  setProtectedHeaders(protectedHeaders: CoseProtectedHeaders) {
    this.protectedHeaders = protectedHeaders;
  }

  getPayload(): CosePayload {
    return this.payload;
  }

  setPayload(payload: CosePayload) {
    this.payload = payload;
  }

  getTag(): CoseTag {
    return this.tag;
  }

  setTag(tag: CoseTag) {
    this.tag = tag;
  }
}
