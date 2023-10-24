import { subtle } from 'uncrypto';
import { cborEncode } from '../cbor';
import { DataItem } from '../cbor/DataItem';
import IssuerAuth from './IssuerAuth';
import { areEqual } from '../buffer_utils';
import { getRandomBytes } from './utils';

const MDL_NAMESPACE = 'org.iso.18013.5.1';

const supportedDigestAlgorithms = ['SHA-256', 'SHA-384', 'SHA-512'];

// eslint-disable-next-line no-use-before-define
export type IssuerSignedDataItem = DataItem<Map<keyof IssuerSignedItem, unknown>>;

export class IssuerSignedItem {
  readonly #dataItem: IssuerSignedDataItem;
  #isValid: boolean | undefined;

  constructor(
    dataItem: IssuerSignedDataItem,
  ) {
    this.#dataItem = dataItem;
  }

  public encode() {
    return this.#dataItem.buffer;
  }

  public get dataItem() {
    return this.#dataItem;
  }

  private get decodedData() {
    if (!this.#dataItem.data.has('digestID')) {
      throw new Error('Invalid data item');
    }
    return this.#dataItem.data;
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

  public async calculateDigest(alg: Parameters<SubtleCrypto['digest']>[0]) {
    const bytes = cborEncode(this.#dataItem);
    const result = await subtle.digest(alg, bytes);
    return result;
  }

  public async isValid(
    nameSpace: string,
    {
      decodedPayload: { valueDigests, digestAlgorithm },
    }: IssuerAuth,
  ): Promise<boolean> {
    if (typeof this.#isValid !== 'undefined') { return this.#isValid; }
    if (!supportedDigestAlgorithms.includes(digestAlgorithm)) {
      this.#isValid = false;
      return false;
    }
    const digest = await this.calculateDigest(digestAlgorithm);
    const digests = valueDigests.get(nameSpace) as Map<number, Uint8Array> | undefined;
    if (typeof digests === 'undefined') { return false; }
    const expectedDigest = digests.get(this.digestID);
    this.#isValid = expectedDigest &&
      areEqual(new Uint8Array(digest), expectedDigest);
    return this.#isValid;
  }

  public matchCertificate(nameSpace: string, { countryName, stateOrProvince }: IssuerAuth): boolean | undefined {
    if (nameSpace !== MDL_NAMESPACE) { return undefined; }

    if (this.elementIdentifier === 'issuing_country') {
      return countryName === this.elementValue;
    }
    if (this.elementIdentifier === 'issuing_jurisdiction') {
      return stateOrProvince === this.elementValue;
    }
    return undefined;
  }

  public static create(
    digestID: number,
    elementIdentifier: string,
    elementValue: any,
  ): IssuerSignedItem {
    const random = getRandomBytes(32);
    const dataItem: IssuerSignedDataItem = DataItem.fromData(new Map([
      ['digestID', digestID],
      ['elementIdentifier', elementIdentifier],
      ['elementValue', elementValue],
      ['random', random],
    ]));
    return new IssuerSignedItem(dataItem);
  }
}
