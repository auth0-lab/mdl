/* eslint-disable no-underscore-dangle */
import { addExtension } from 'cbor-x';
import util from 'util';
import { cborDecode, cborEncode } from '.';

export type DataItemParams<T = any> = {
  data: T,
  buffer: Uint8Array,
} | { data: T } | { buffer: Uint8Array };

/**
 * DataItem is an extension defined https://www.rfc-editor.org/rfc/rfc8949.html#name-encoded-cbor-data-item
 *  > Sometimes it is beneficial to carry an embedded CBOR data item that is
 *  > not meant to be decoded immediately at the time the enclosing data item is being decoded.
 *
 * The idea of this class is to provide lazy encode and decode of cbor data.
 *
 * Due to a bug in the cbor-x library, we are eagerly encoding the data in the constructor.
 * https://github.com/kriszyp/cbor-x/issues/83
 *
 */
export class DataItem<T = any> {
  #data: T;
  #buffer: Uint8Array;

  constructor(params: DataItemParams<T>) {
    if (
      !('data' in params) &&
      !('buffer' in params)
    ) {
      throw new Error('DataItem must be initialized with either data or buffer');
    }
    if ('data' in params) {
      this.#data = params.data;

      // TODO: remove this once fixed in cbor-x
      // https://github.com/kriszyp/cbor-x/issues
      if (!('buffer' in params)) {
        this.#buffer = cborEncode(this.#data);
      }
    }

    if ('buffer' in params) {
      this.#buffer = params.buffer;
    }
  }

  public get data(): T {
    if (!this.#data) {
      this.#data = cborDecode(this.#buffer) as T;
    }
    return this.#data;
  }

  public get buffer(): Uint8Array {
    if (!this.#buffer) {
      this.#buffer = cborEncode(this.#data, { useFloat32: 0 });
    }
    return this.#buffer;
  }

  public static fromData<T>(data: T): DataItem<T> {
    return new DataItem({ data });
  }
}

addExtension({
  Class: DataItem,
  tag: 24,
  encode: (instance: DataItem<any>, encode) => {
    return encode(instance.buffer);
  },
  decode: (buffer: Uint8Array): Object => {
    return new DataItem({ buffer });
  },
});
