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

  static fromJSON(json: any): MDoc {
    const documents = json.documents.map((docJson: any) => {
      // Reconstruct Buffers
      const auth = docJson.issuerSigned.issuerAuth;
      ['payload', 'signature', 'encodedProtectedHeaders'].forEach((key) => {
        if (auth[key]?.type === 'Buffer') {
          auth[key] = Buffer.from(auth[key].data);
        }
      });
  
      // Re-add method
      auth.getContentForEncoding = function () {
        return {
          protected: this.encodedProtectedHeaders,
          unprotected: this.unprotectedHeaders,
          payload: this.payload,
          signature: this.signature,
        };
      };
  
      // Reconstruct IssuerSignedDocument
      const issuerSigned = {
        ...docJson.issuerSigned,
        issuerAuth: auth,
      };
  
      return new IssuerSignedDocument(docJson.docType, issuerSigned);
    });
  
    return new MDoc(documents);
  }
}
