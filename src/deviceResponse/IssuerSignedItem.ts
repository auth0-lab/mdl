import crypto from 'crypto';
import { cborEncode } from '../cose/cbor';
import { DataItem } from '../cose/DataItem';

// eslint-disable-next-line no-use-before-define
export type IssuerSignedDataItem = DataItem<Map<keyof IssuerSignedItem, unknown>>;

export class IssuerSignedItem {
  private readonly dataItem: IssuerSignedDataItem;

  constructor(dataItem: IssuerSignedDataItem) {
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

  public get random(): Buffer {
    return this.decodedData.get('random') as Buffer;
  }

  public get elementIdentifier(): string {
    return this.decodedData.get('elementIdentifier') as string;
  }

  public get elementValue(): any {
    return this.decodedData.get('elementValue');
  }

  public async calculateDigest(alg: crypto.webcrypto.AlgorithmIdentifier) {
    const bytes = cborEncode(this.dataItem);
    const result = await crypto.subtle.digest(alg, bytes);
    return result;
  }
}
