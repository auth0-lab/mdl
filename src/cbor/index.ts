import {
  addExtension,
  Encoder,
  Options,
} from 'cbor-x';

export class FullDate extends Date {
  constructor(strDate?: string) {
    super(strDate);
  }

  toString(): string {
    return super.toISOString().split('T')[0];
  }

  toISOString(): string {
    return super.toISOString().split('T')[0];
  }
}

const encoderDefaults: Options = {
  tagUint8Array: false,
  useRecords: false,
  mapsAsObjects: false,
  // @ts-ignore
  useTag259ForMaps: false,
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
  Class: FullDate,
  tag: 1004,
  encode: (date: FullDate, encode) => encode(date.toISOString()),
  decode: (isoStringDate: any): Object => new FullDate(isoStringDate),
});

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
