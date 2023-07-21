import { decode, encode } from 'cbor';
// eslint-disable-next-line import/no-unresolved
import { BufferLike } from 'cbor/types/lib/decoder';

const extraTags = {
  // tag value 24 indicates that the content of the CBOR bstr
  // following the tag is itself a CBOR data item
  24: (value: Buffer) => decode(value, { tags: extraTags }),
  1004: (dateString: string) => dateString,
};

export const cborDecode = (
  input: BufferLike,
  options: { skipExtraTags?: boolean } = {},
): unknown => decode(input, options.skipExtraTags ? {} : { tags: extraTags });

export const cborEncode = (obj: unknown): Buffer => encode(obj);
