import { cborEncode } from '../../cbor';
import { IssuerSignedDocument } from './IssuerSignedDocument';

export type ErrorCode = number;
export type ErrorItems = Record<string, ErrorCode>;
export type DocumentError = {
  DocType: ErrorCode;
};

export enum MDocStatus {
  OK = 0,
  GeneralError = 10,
  CBORDecodingError = 11,
  CBORValidationError = 12,
}

export class MDoc {
  constructor(
    public readonly documents: IssuerSignedDocument[] = [],
    public readonly version = '1.0',
    public readonly status: MDocStatus = MDocStatus.OK,
    public readonly documentErrors: DocumentError[] = [],
  ) { }

  addDocument(document: IssuerSignedDocument) {
    if (typeof document.issuerSigned === 'undefined') {
      throw new Error('Cannot add an unsigned document');
    }
    this.documents.push(document as IssuerSignedDocument);
  }

  encode() {
    return cborEncode({
      version: this.version,
      documents: this.documents.map((doc) => doc.prepare()),
      status: this.status,
    });
  }
}
