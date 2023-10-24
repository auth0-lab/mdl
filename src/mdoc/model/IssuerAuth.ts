import { Sign1 } from 'cose-kit';
import { X509Certificate } from '@peculiar/x509';
import { cborDecode } from '../../cbor';
import { DataItem } from '../../cbor/DataItem';
import { MSO } from './types';

/**
 * The IssuerAuth which is a COSE_Sign1 message
 * as defined in https://www.iana.org/assignments/cose/cose.xhtml#messages
 */
export default class IssuerAuth extends Sign1 {
  #decodedPayload: MSO;
  #certificate: X509Certificate;

  constructor(
    protectedHeader: Map<number, unknown> | Uint8Array,
    unprotectedHeader: Map<number, unknown>,
    payload: Uint8Array,
    signature: Uint8Array,
  ) {
    super(protectedHeader, unprotectedHeader, payload, signature);
  }

  public get decodedPayload(): MSO {
    if (this.#decodedPayload) { return this.#decodedPayload; }
    let decoded = cborDecode(this.payload);
    decoded = decoded instanceof DataItem ? decoded.data : decoded;
    decoded = Object.fromEntries(decoded);
    const mapValidityInfo = (validityInfo: Map<string, Uint8Array>) => {
      if (!validityInfo) { return validityInfo; }
      return Object.fromEntries([...validityInfo.entries()].map(([key, value]) => {
        return [key, value instanceof Uint8Array ? cborDecode(value) : value];
      }));
    };
    const result: MSO = {
      ...decoded,
      validityInfo: mapValidityInfo(decoded.validityInfo),
      validityDigests: decoded.validityDigests ? Object.fromEntries(decoded.validityDigests) : decoded.validityDigests,
      deviceKeyInfo: decoded.deviceKeyInfo ? Object.fromEntries(decoded.deviceKeyInfo) : decoded.deviceKeyInfo,
    };
    this.#decodedPayload = result;
    return result;
  }

  public get certificate() {
    if (typeof this.#certificate === 'undefined' && this.x5chain?.length) {
      this.#certificate = new X509Certificate(this.x5chain[0]);
    }
    return this.#certificate;
  }

  public get countryName() {
    return this.certificate?.issuerName.getField('C')[0];
  }

  public get stateOrProvince() {
    return this.certificate?.issuerName.getField('ST')[0];
  }
}
