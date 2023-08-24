import {
  addExtension,
  Encoder,
  Options
} from 'cbor-x';

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
  encode: (instance, encode) => {
    return encode(instance);
  },
  decode: (val: any): Object => {
    // return val instanceof Uint8Array ? decode(val) : val;
    return encoder.decode(val);
  }
});

const encoderDefaults: Options = {
  tagUint8Array: false,
  useRecords: false,
  mapsAsObjects: true
};

const encoder = new Encoder(encoderDefaults);

export const cborDecode = (
  input: Buffer | Uint8Array,
  options: Options = encoderDefaults
): any => {
  const encoder = new Encoder({ ...encoderDefaults, ...options });
  return encoder.decode(input);
};

export const cborEncode = (obj: unknown): Buffer => encoder.encode(obj);
