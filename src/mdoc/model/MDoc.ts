import { cborEncode } from '../../cbor';
import { IssuerSignedDoc, Document, prepare } from './Document';

export class MDoc {
  constructor(
    public readonly documents: IssuerSignedDoc[] = [],
    public readonly version = '1.0',
    public readonly status = 0,
  ) { }

  addDocument(document: IssuerSignedDoc | Document) {
    if (typeof document.issuerSigned === 'undefined') {
      throw new Error('Cannot add an unsigned document');
    }
    this.documents.push(document as IssuerSignedDoc);
  }

  encode() {
    return cborEncode({
      version: this.version,
      documents: this.documents.map(prepare),
      status: this.status,
    });
  }
}
