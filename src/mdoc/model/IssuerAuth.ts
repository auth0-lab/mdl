import { ProtectedHeaders, Sign1, UnprotectedHeaders } from 'cose-kit';
import { X509Certificate } from '@peculiar/x509';
import { KeyLike } from 'jose';
import { cborDecode, cborEncode } from '../../cbor';
import { DataItem } from '../../cbor/DataItem';
import { MSO, SupportedAlgs } from './types';
import { Signer } from '../signing/Signer';

// COSE Header parameter constants
// Reference: https://www.iana.org/assignments/cose/cose.xhtml#header-parameters
const COSE_HEADERS = {
  ALG: 1,
  CRIT: 2,
  CONTENT_TYPE: 3,
  KID: 4,
  IV: 5,
  PARTIAL_IV: 6,
  X5CHAIN: 33,
};

// COSE Algorithm identifiers
// Reference: https://www.iana.org/assignments/cose/cose.xhtml#algorithms
const COSE_ALG_MAP: Record<SupportedAlgs, number> = {
  EdDSA: -8,
  ES256: -7,
  ES384: -35,
  ES512: -36,
};

/**
 * Convert ProtectedHeaders to a Map for CBOR encoding
 */
function protectedHeadersToMap(headers: ProtectedHeaders): Map<number, unknown> {
  const map = new Map<number, unknown>();

  if (headers.alg) {
    const algValue = COSE_ALG_MAP[headers.alg as SupportedAlgs];
    if (algValue !== undefined) {
      map.set(COSE_HEADERS.ALG, algValue);
    }
  }

  if (headers.crit) {
    map.set(COSE_HEADERS.CRIT, headers.crit);
  }

  if (headers.ctyp !== undefined) {
    map.set(COSE_HEADERS.CONTENT_TYPE, headers.ctyp);
  }

  // Handle any custom headers
  for (const [key, value] of Object.entries(headers)) {
    if (key !== 'alg' && key !== 'crit' && key !== 'ctyp') {
      const numKey = typeof key === 'string' ? parseInt(key, 10) : key;
      if (!Number.isNaN(numKey)) {
        map.set(numKey, value);
      }
    }
  }

  return map;
}

/**
 * Convert UnprotectedHeaders to a Map for COSE structure
 */
function unprotectedHeadersToMap(headers: UnprotectedHeaders | undefined): Map<number, unknown> {
  const map = new Map<number, unknown>();

  if (!headers) {
    return map;
  }

  if (headers.ctyp !== undefined) {
    map.set(COSE_HEADERS.CONTENT_TYPE, headers.ctyp);
  }

  if (headers.kid !== undefined) {
    map.set(COSE_HEADERS.KID, headers.kid);
  }

  if (headers.x5chain !== undefined) {
    map.set(COSE_HEADERS.X5CHAIN, headers.x5chain);
  }

  // Handle any custom headers
  for (const [key, value] of Object.entries(headers)) {
    if (key !== 'ctyp' && key !== 'kid' && key !== 'x5chain') {
      const numKey = typeof key === 'string' ? parseInt(key, 10) : key;
      if (!Number.isNaN(numKey)) {
        map.set(numKey, value);
      }
    }
  }

  return map;
}

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

  static async sign(
    protectedHeaders: ProtectedHeaders,
    unprotectedHeaders: UnprotectedHeaders | undefined,
    payload: Uint8Array,
    key: KeyLike | Uint8Array,
  ): Promise<IssuerAuth> {
    const sign1 = await Sign1.sign(protectedHeaders, unprotectedHeaders, payload, key);
    return new IssuerAuth(
      sign1.protectedHeaders,
      sign1.unprotectedHeaders,
      sign1.payload,
      sign1.signature,
    );
  }

  /**
   * Sign using a Signer interface (e.g., AzureKeyVaultSigner)
   * This method manually constructs the COSE_Sign1 structure to support custom signing mechanisms
   *
   * @param protectedHeaders - The protected headers
   * @param unprotectedHeaders - The unprotected headers
   * @param payload - The payload to sign
   * @param signer - The Signer implementation
   * @param alg - The algorithm to use
   * @returns The signed IssuerAuth
   */
  static async signWithSigner(
    protectedHeaders: ProtectedHeaders,
    unprotectedHeaders: UnprotectedHeaders | undefined,
    payload: Uint8Array,
    signer: Signer,
    alg: SupportedAlgs,
  ): Promise<IssuerAuth> {
    // Convert headers to Maps
    const protectedHeadersMap = protectedHeadersToMap(protectedHeaders);

    // Ensure alg is set in protected headers
    if (!protectedHeadersMap.has(COSE_HEADERS.ALG)) {
      protectedHeadersMap.set(COSE_HEADERS.ALG, COSE_ALG_MAP[alg]);
    }

    // Encode the protected headers
    const encodedProtectedHeaders = cborEncode(protectedHeadersMap);

    // Convert unprotected headers to Map
    const unprotectedHeadersMap = unprotectedHeadersToMap(unprotectedHeaders);

    // Construct the Sig_structure as per RFC 8152 Section 4.4
    // Sig_structure = [
    //   context: "Signature1",
    //   protected: serialized_protected_headers,
    //   external_aad: empty_or_serialized_aad,
    //   payload: payload
    // ]
    const toBeSigned = cborEncode([
      'Signature1',
      encodedProtectedHeaders,
      new Uint8Array(), // external_aad (empty for normal signing)
      payload,
    ]);

    // Sign using the custom signer
    const signature = await signer.sign(alg, new Uint8Array(toBeSigned));

    return new IssuerAuth(
      new Uint8Array(encodedProtectedHeaders),
      unprotectedHeadersMap,
      payload,
      signature,
    );
  }
}
