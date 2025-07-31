import {
  addExtension,
  Encoder,
  Options,
} from 'cbor-x';

const customInspectSymbol = Symbol.for('nodejs.util.inspect.custom');

export class DateOnly extends Date {
  constructor(strDate?: string) {
    super(strDate);
  }

  get [Symbol.toStringTag]() {
    return DateOnly.name;
  }

  toISOString(): string {
    return super.toISOString().split('T')[0];
  }

  toString(): string {
    return this.toISOString();
  }

  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  toJSON(key?: any): string {
    return this.toISOString();
  }

  [customInspectSymbol](): string {
    return this.toISOString();
  }
}

let encoderDefaults: Options = {
  tagUint8Array: false,
  useRecords: false,
  mapsAsObjects: false,
  // @ts-ignore
  useTag259ForMaps: false,
  variableMapSize: true,
};

// tdate data item shall contain a date-time string as specified in RFC 3339 (with no fraction of seconds)
// see https://datatracker.ietf.org/doc/html/rfc3339#section-5.6
addExtension({
  Class: Date,
  tag: 0,
  encode: (date: Date, encode) => encode(`${date.toISOString().split('.')[0]}Z`),
  decode: (isoStringDateTime: any) => new Date(isoStringDateTime),
});

// full-date data item shall contain a full-date string as specified in RFC 3339
// see https://datatracker.ietf.org/doc/html/rfc3339#section-5.6
addExtension({
  Class: DateOnly,
  tag: 1004,
  encode: (date: DateOnly, encode) => encode(date.toISOString()),
  decode: (isoStringDate: any): Object => new DateOnly(isoStringDate),
});

export const getCborEncodeDecodeOptions = () : Options => {
  return encoderDefaults;
};

export const setCborEncodeDecodeOptions = (options: Options) : void => {
  encoderDefaults = options;
};

export const cborDecode = (
  input: Buffer | Uint8Array,
  options: Options = encoderDefaults,
): any => {
  const params = { ...encoderDefaults, ...options };
  const enc = new Encoder(params);
  return enc.decode(input);
};

export const cborEncode = (
  obj: unknown,
  options: Options = encoderDefaults,
): Buffer => {
  const params = { ...encoderDefaults, ...options };
  const enc = new Encoder(params);
  return enc.encode(obj);
};

export { DataItem } from './DataItem';
