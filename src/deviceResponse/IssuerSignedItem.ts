import { subtle } from 'uncrypto';
import { cborEncode } from '../cbor';
import { DataItem } from '../cbor/DataItem';
import IssuerAuth from './IssuerAuth';
import { areEqual } from '../buffer_utils';

const supportedDigestAlgorithms = ['SHA-256', 'SHA-384', 'SHA-512'];

// eslint-disable-next-line no-use-before-define
export type IssuerSignedDataItem = DataItem<Map<keyof IssuerSignedItem, unknown>>;

export class IssuerSignedItem {
  private readonly dataItem: IssuerSignedDataItem;
  #issuerAuth: IssuerAuth;
  #nameSpace: string;
  #isValid: boolean | undefined;

  constructor(
    issuerAuth: IssuerAuth,
    nameSpace: string,
    dataItem: IssuerSignedDataItem,
  ) {
    this.#issuerAuth = issuerAuth;
    this.#nameSpace = nameSpace;
    this.dataItem = dataItem;
  }

  private get decodedData() {
    if (!this.dataItem.data.has('digestID')) {
      throw new Error('Invalid data item');
    }
    return this.dataItem.data;
  }

  public get digestID(): number {
    return this.decodedData.get('digestID') as number;
  }

  public get random(): Uint8Array {
    return this.decodedData.get('random') as Uint8Array;
  }

  public get elementIdentifier(): string {
    return this.decodedData.get('elementIdentifier') as string;
  }

  public get elementValue(): any {
    return this.decodedData.get('elementValue');
  }

  private async calculateDigest(alg: Parameters<SubtleCrypto['digest']>[0]) {
    const bytes = cborEncode(this.dataItem);
    const result = await subtle.digest(alg, bytes);
    return result;
  }

  public async isValid(): Promise<boolean> {
    if (typeof this.#isValid !== 'undefined') { return this.#isValid; }
    const { valueDigests, digestAlgorithm } = this.#issuerAuth.decodedPayload;
    if (!supportedDigestAlgorithms.includes(digestAlgorithm)) {
      this.#isValid = false;
      return false;
    }
    const digest = await this.calculateDigest(digestAlgorithm);
    const digests = valueDigests.get(this.#nameSpace) as Map<number, Uint8Array> | undefined;
    if (typeof digests === 'undefined') { return false; }
    const expectedDigest = digests.get(this.digestID);
    this.#isValid = expectedDigest &&
      areEqual(new Uint8Array(digest), expectedDigest);
    return this.#isValid;
  }
}
