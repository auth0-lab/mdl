import { Buffer } from 'buffer';
import { Crypto } from '@peculiar/webcrypto';
import { cborDecode, cborEncode } from './cbor';
import {
  CosePayload,
  CoseProtectedHeaders,
  CoseSignature,
  CoseUnprotectedHeaders,
} from './cose';

/**
 * A COSE_Sign1 structure (https://datatracker.ietf.org/doc/html/rfc8152#section-4.2)
 *
 */
export default class CoseSign1 {
  private protectedHeaders: CoseProtectedHeaders;

  private unprotectedHeaders: CoseUnprotectedHeaders;

  private payload: CosePayload;

  private signature: CoseSignature;

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

  /* Getters and setters */
  getProtectedHeaders(): CoseProtectedHeaders {
    return this.protectedHeaders;
  }

  setProtectedHeaders(protectedHeaders: CoseProtectedHeaders) {
    this.protectedHeaders = protectedHeaders;
  }

  getUnprotectedHeaders(): CoseUnprotectedHeaders {
    return this.unprotectedHeaders;
  }

  setUnprotectedHeaders(unprotectedHeaders: CoseUnprotectedHeaders) {
    this.unprotectedHeaders = unprotectedHeaders;
  }

  getPayload(): CosePayload {
    return this.payload;
  }

  setPayload(payload: CosePayload) {
    this.payload = payload;
  }

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  getDecodedPayload(): any {
    return cborDecode(this.payload);
  }

  getSignature(): CoseSignature {
    return this.signature;
  }

  setSignature(signature: CoseSignature) {
    this.signature = signature;
  }

  async verify(publicKey: ArrayBuffer, detachedContent?: Buffer) {
    // https://datatracker.ietf.org/doc/html/rfc8152#section-4.4
    const ToBeSigned = cborEncode([
      'Signature1',
      this.protectedHeaders,
      Buffer.alloc(0),
      this.payload.length > 0 ? this.payload : detachedContent,
    ]);

    const crypto = new Crypto();
    const pk = await crypto.subtle.importKey(
      'spki',
      publicKey,
      { name: 'ECDSA', namedCurve: 'P-256' },
      true,
      ['verify'],
    );

    return crypto.subtle.verify(
      { name: 'ECDSA', hash: 'sha-256' },
      pk,
      this.getSignature(),
      ToBeSigned,
    );
  }
}
