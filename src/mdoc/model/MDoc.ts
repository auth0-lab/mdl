import { cborEncode } from '../../cbor';
import { IssuerSignedDocument } from './IssuerSignedDocument';

export class MDoc {
  constructor(
    public readonly documents: IssuerSignedDocument[] = [],
    public readonly version = '1.0',
    public readonly status = 0,
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
