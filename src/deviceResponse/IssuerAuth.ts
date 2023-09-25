import { Sign1 } from 'cose';
import { cborDecode } from '../cbor';
import { DataItem } from '../cbor/DataItem';
import { ValidityInfo } from './types';

type Payload = {
  digestAlgorithm: string;
  docType: string;
  version: string;

  valueDigests: Map<string, Map<number, Uint8Array>>;

  validityInfo: ValidityInfo;

  validityDigests: {
    [key: string]: Map<number, Uint8Array>;
  };

  deviceKeyInfo?: {
    deviceKey: Map<number, Uint8Array | number>;
    [key: string]: any;
  };
};

/**
 * The IssuerAuth which is a COSE_Sign1 message
 * as defined in https://www.iana.org/assignments/cose/cose.xhtml#messages
 */
export default class IssuerAuth extends Sign1 {
  #decodedPayload: Payload;

  constructor(
    protectedHeader: Map<number, unknown> | Uint8Array,
    unprotectedHeader: Map<number, unknown>,
    payload: Uint8Array,
    signature: Uint8Array,
  ) {
    super(protectedHeader, unprotectedHeader, payload, signature);
  }

  public get decodedPayload(): Payload {
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
    const result: Payload = {
      ...decoded,
      validityInfo: mapValidityInfo(decoded.validityInfo),
      validityDigests: decoded.validityDigests ? Object.fromEntries(decoded.validityDigests) : decoded.validityDigests,
      deviceKeyInfo: decoded.deviceKeyInfo ? Object.fromEntries(decoded.deviceKeyInfo) : decoded.deviceKeyInfo,
    };
    this.#decodedPayload = result;
    return result;
  }
}
