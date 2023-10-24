import * as jose from 'jose';
import { COSEKeyFromJWK, ProtectedHeader, UnprotectedHeaders } from 'cose-kit';
import { fromPEM } from '../utils';
import { DataItem, cborEncode } from '../../cbor';
import { IssuerSignedItem } from '../IssuerSignedItem';
import IssuerAuth from '../IssuerAuth';
import { DeviceSigned, IssuerNameSpaces, IssuerSigned } from '../types';

const DEFAULT_NS = 'org.iso.18013.5.1';

const getAgeInYears = (birth: string): number => {
  const birthDate = new Date(birth);
  birthDate.setHours(0, 0, 0, 0);
  // @ts-ignore
  const ageDifMs = Date.now() - birthDate;
  const ageDate = new Date(ageDifMs);
  return Math.abs(ageDate.getUTCFullYear() - 1970);
};

// eslint-disable-next-line no-use-before-define
export type SignedDocument = Document & { issuerSigned: IssuerSigned };

export class Document {
  #nameSpaces: IssuerNameSpaces = {};
  #issuerSigned?: IssuerSigned;
  #deviceSigned?: DeviceSigned;

  constructor(
    public readonly docType: 'org.iso.18013.5.1.mDL' | string = 'org.iso.18013.5.1.mDL',
    issuerSigned?: IssuerSigned,
    deviceSigned?: DeviceSigned,
  ) {
    this.#issuerSigned = issuerSigned;
    this.#deviceSigned = deviceSigned;
  }

  get issuerSigned() {
    return this.#issuerSigned;
  }

  get deviceSigned() {
    return this.#deviceSigned;
  }

  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  private validateValues(values: Record<string, any>) {
    // TODO
    // validate required fields, no extra fields, data types, etc...
  }

  /**
   * Add a namespace to an unsigned document.
   *
   * @param {string} namespace - The namespace to add.
   * @param {Record<string, any>} values - The values to add to the namespace.
   * @returns {Document} - The document
   */
  addNameSpace(namespace: 'org.iso.18013.5.1' | string, values: Record<string, any>): Document {
    if (this.issuerSigned) {
      throw new Error('Cannot add namespace to an already signed document');
    }
    if (namespace === DEFAULT_NS) {
      this.validateValues(values);
    }
    this.#nameSpaces[namespace] = this.#nameSpaces[namespace] ?? [];

    const addAttribute = (key: string, value: any) => {
      const digestID = this.#nameSpaces[namespace].length;
      const issuerSignedItem = IssuerSignedItem.create(digestID, key, value);
      this.#nameSpaces[namespace].push(issuerSignedItem);
    };

    for (const [key, value] of Object.entries(values)) {
      addAttribute(key, value);
      if (key === 'birth_date') {
        const ageInYears = getAgeInYears(value);
        addAttribute('age_over_21', ageInYears >= 21);
        addAttribute(`age_over_${Math.floor(ageInYears)}`, Math.floor(ageInYears));
      }
    }

    return this;
  }

  /**
   * Sign the document.
   *
   * @param params.issuerPrivateKey - The issuer's private key
   * @param params.issuerCertificate - The issuer's certificate in pem format.
   * @param params.devicePublicKey - The device's public key
   * @returns {Promise<SignedDocument>} - The signed document
   */
  async sign(params: {
    issuerPrivateKey: jose.KeyLike,
    issuerCertificate: string,
    devicePublicKey: jose.KeyLike | Uint8Array,
  }): Promise<SignedDocument> {
    if (this.issuerSigned) {
      throw new Error('Cannot add namespace to an already signed document');
    }
    if (!this.#nameSpaces) {
      throw new Error('No namespaces added');
    }

    const digestAlgo = 'SHA-256';
    const devicePublicKeyJwk = await jose.exportJWK(params.devicePublicKey);
    const issuerPublicKeyBuffer = fromPEM(params.issuerCertificate);
    const utcNow = new Date();
    const expTime = new Date();
    expTime.setFullYear(expTime.getFullYear() + 4);

    const signedDate = utcNow;
    const validFromDate = utcNow;
    const validUntilDate = expTime;

    const deviceKey = COSEKeyFromJWK(devicePublicKeyJwk);

    const valueDigests = new Map(await Promise.all(Object.entries(this.#nameSpaces).map(async ([namespace, items]) => {
      const digestMap = new Map<number, Uint8Array>();
      await Promise.all(items.map(async (item, index) => {
        const hash = await item.calculateDigest(digestAlgo);
        digestMap.set(index, new Uint8Array(hash));
      }));
      return [namespace, digestMap] as [string, Map<number, Uint8Array>];
    })));

    const mso = {
      version: '1.0',
      digestAlgorithm: digestAlgo,
      valueDigests,
      deviceKeyInfo: {
        deviceKey,
      },
      docType: this.docType,
      validityInfo: {
        signed: signedDate,
        validFrom: validFromDate,
        validUntil: validUntilDate,
      },
    };

    const payload = cborEncode(DataItem.fromData(mso));
    const protectedHeader: ProtectedHeader = { alg: 'ES256' };
    const unprotectedHeader: UnprotectedHeaders = { kid: '11', x5chain: [issuerPublicKeyBuffer] };
    const issuerAuth = await IssuerAuth.sign(protectedHeader, unprotectedHeader, payload, params.issuerPrivateKey) as IssuerAuth;

    this.#issuerSigned = {
      issuerAuth,
      nameSpaces: this.#nameSpaces,
    };

    return this;
  }

  /**
   * Create the structure for encoding the document.
   *
   * @returns {Map<string, any>} - The document as a map
   */
  public prepare(): Map<string, any> {
    const docMap = new Map<string, any>();
    docMap.set('docType', this.docType);
    docMap.set('issuerSigned', {
      nameSpaces: new Map(Object.entries(this.issuerSigned?.nameSpaces ?? {}).map(([nameSpace, items]) => {
        return [nameSpace, items.map((item) => item.dataItem)];
      })),
      issuerAuth: this.issuerSigned?.issuerAuth.getContentForEncoding(),
    });
    if (typeof this.deviceSigned !== 'undefined') {
      // TODO
      docMap.set('deviceSigned', this.deviceSigned);
    }
    return docMap;
  }
}
