import { subtle } from 'uncrypto';
import { cborEncode } from '../cbor';
import { DataItem } from '../cbor/DataItem';

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
    const bytes = cborEncode(this.dataItem);
    const result = await subtle.digest(alg, bytes);
    return result;
  }
}
