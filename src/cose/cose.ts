import { Buffer } from 'buffer';

export type CoseProtectedHeaders = Buffer;
export type CoseUnprotectedHeaders = Map<number, Buffer>;
export type CosePayload = Buffer;
export type CoseSignature = Buffer;
export type CoseTag = Buffer;

export enum Header {
  algorithm = 1,
  kid = 4,
  x5chain = 33,
}

export enum CoseMacAlgorithm {
  HMAC_256_256 = 5,
}
