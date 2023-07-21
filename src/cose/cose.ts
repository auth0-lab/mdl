import { Buffer } from 'buffer';

export type CoseProtectedHeaders = Buffer;
export type CoseUnprotectedHeaders = Map<number, Buffer>;
export type CosePayload = Buffer;
export type CoseSignature = Buffer;
export type CoseTag = Buffer;
