import {
  addExtension,
  decode,
  encode
} from 'cbor-x';
import CoseSign1 from './CoseSign1';

addExtension({
  Class: Date,
  tag: 1004,
  encode: (instance: Date, encode) => {
    const str = instance.toISOString().split('T')[0];
    return encode(str);
  },
  decode: (val: any): Object => {
    return new Date(val);
  }
});

addExtension({
  Class: Object,
  tag: 24,
  encode: (instance, val) => {
    return encode(instance);
  },
  decode: (val: any): Object => {
    // return val instanceof Uint8Array ? decode(val) : val;
    return decode(val);
  }
});

// addExtension({
//   Class: CoseSign1,
//   tag: 18,
//   encode: (instance: CoseSign1, val) => {
//     throw new Error('Not implemented');
//   },
//   decode: (val: any): Object => {
//     //decode(val)
//     return val instanceof Uint8Array ? decode(val) : val;
//   }
// });

export const cborDecode = (
  input: Buffer | Uint8Array,
  options: { skipExtraTags?: boolean } = {},
): unknown => decode(input);

export const cborEncode = (obj: unknown): Buffer => encode(obj);
