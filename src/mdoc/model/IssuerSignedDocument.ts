import { DocType, IssuerSigned } from './types';

/**
 * Represents an issuer signed document.
 *
 * Note: You don't need instantiate this class.
 * This is the return type of the parser and the document.sign() method.
 */
export class IssuerSignedDocument {
  constructor(
    public readonly docType: DocType,
    public readonly issuerSigned: IssuerSigned,
  ) { }

  /**
   * Create the structure for encoding a document.
   *
   * @returns {Map<string, any>} - The document as a map
   */
  prepare(): Map<string, any> {
    const docMap = new Map<string, any>();
    docMap.set('docType', this.docType);
    docMap.set('issuerSigned', {
      nameSpaces: new Map(Object.entries(this.issuerSigned?.nameSpaces ?? {}).map(([nameSpace, items]) => {
        return [nameSpace, items.map((item) => item.dataItem)];
      })),
      issuerAuth: this.issuerSigned?.issuerAuth.getContentForEncoding(),
    });
    return docMap;
  }

  /**
   * Helper method to get the values in a namespace as a JS object.
   *
   * @param {string} namespace - The namespace to add.
   * @returns {Record<string, any>} - The values in the namespace as an object
   */
  getIssuerNameSpace(namespace: string): Record<string, any> {
    const nameSpace = this.issuerSigned.nameSpaces[namespace];
    return Object.fromEntries(
      nameSpace.map((item) => [item.elementIdentifier, item.elementValue]),
    );
  }

  /**
   * List of namespaces in the document.
   */
  get issuerSignedNameSpaces(): string[] {
    return Object.keys(this.issuerSigned.nameSpaces);
  }
}
