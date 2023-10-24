import { cborEncode } from '../../cbor';
import { SignedDocument, Document } from './Document';

export class MDoc {
  constructor(
    public readonly documents: SignedDocument[] = [],
    public readonly version = '1.0',
    public readonly status = 0,
  ) { }

  addDocument(document: SignedDocument | Document) {
    if (typeof document.issuerSigned === 'undefined') {
      throw new Error('Cannot add an unsigned document');
    }
    this.documents.push(document as SignedDocument);
  }

  encode() {
    return cborEncode({
      version: this.version,
      documents: this.documents.map((doc) => doc.prepare()),
      status: this.status,
    });
  }
}
