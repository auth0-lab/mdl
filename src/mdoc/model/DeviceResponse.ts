import * as jose from 'jose';
import { COSEKeyToJWK, Sign1 } from 'cose-kit';
import { InputDescriptor, PresentationDefinition } from './PresentationDefinition';
import { MDoc } from './MDoc';
import { DeviceAuth, DeviceSigned, SupportedAlgs } from './types';
import { DeviceSignedDocument, IssuerSignedDocument } from './IssuerSignedDocument';
import { IssuerSignedItem } from '../IssuerSignedItem';
import { parse } from '../parser';
import { calculateDeviceAutenticationBytes } from '../utils';

const DOC_TYPE = 'org.iso.18013.5.1.mDL';

/**
 * A builder class for creating a device response.
 */
export class DeviceResponse {
  private mdoc: MDoc;
  private pd: PresentationDefinition;
  private handover: string[];
  private useMac = true;
  private devicePrivateKey: jose.JWK;
  private readerPublicKey: jose.KeyLike;
  public deviceResponseCbor: Buffer;
  public nameSpaces: Record<string, Record<string, any>> = {};
  private alg: SupportedAlgs;

  /**
   * Create a DeviceResponse builder.
   *
   * @param {MDoc | Uint8Array} mdoc - The mdoc to use as a base for the device response.
   *                                   It can be either a parsed MDoc or a CBOR encoded MDoc.
   * @returns {DeviceResponse} - A DeviceResponse builder.
   */
  public static from(mdoc: MDoc | Uint8Array): DeviceResponse {
    if (mdoc instanceof Uint8Array) {
      return new DeviceResponse(parse(mdoc));
    }
    return new DeviceResponse(mdoc);
  }

  constructor(mdoc: MDoc) {
    this.mdoc = mdoc;
  }

  /**
   *
   * @param pd - The presentation definition to use for the device response.
   * @returns {DeviceResponse}
   */
  public usingPresentationDefinition(pd: PresentationDefinition): DeviceResponse {
    this.pd = pd;
    return this;
  }

  /**
   * Set the handover data to use for the device response.
   *
   * @param {string[]} handover - The handover data to use for the device response.
   * @returns {DeviceResponse}
   */
  public usingHandover(handover: string[]): DeviceResponse {
    this.handover = handover;
    return this;
  }

  /**
   * Add a name space to the device response.
   *
   * @param {string} nameSpace - The name space to add to the device response.
   * @param {Record<string, any>} data - The data to add to the name space.
   * @returns {DeviceResponse}
   */
  public addDeviceNameSpace(nameSpace: string, data: Record<string, any>): DeviceResponse {
    this.nameSpaces[nameSpace] = data;
    return this;
  }

  /**
   * Set the device's private key to be used for signing the device response.
   *
   * @param  {jose.JWK | Uint8Array} devicePrivateKey - The device's private key either as a JWK or a COSEKey.
   * @param  {SupportedAlgs} alg - The algorithm to use for signing the device response.
   * @returns {DeviceResponse}
   */
  public authenticateWithSignature(
    devicePrivateKey: jose.JWK | Uint8Array,
    alg: SupportedAlgs,
  ): DeviceResponse {
    if (devicePrivateKey instanceof Uint8Array) {
      this.devicePrivateKey = COSEKeyToJWK(devicePrivateKey);
    } else {
      this.devicePrivateKey = devicePrivateKey;
    }
    this.alg = alg;
    this.useMac = false;
    return this;
  }

  /**
   * Sign the device response and return the MDoc.
   *
   * @returns {Promise<MDoc>} - The device response as an MDoc.
   */
  public async sign(): Promise<MDoc> {
    if (!this.pd) throw new Error('Must provide a presentation definition with .usingPresentationDefinition()');
    if (!this.handover) throw new Error('Must provide handover data with .usingHandover()');

    const inputDescriptor = this.pd.input_descriptors.find((id) => id.id === DOC_TYPE);

    if (!inputDescriptor) {
      throw new Error(
        `The presentation definition does not include an input descriptor for the default DocType "${DOC_TYPE}"`,
      );
    }

    if (this.pd.input_descriptors.length > 1) {
      console.warn(
        `Presentation definition includes input_descriptors for unsupported DocTypes. Only "${DOC_TYPE}" is supported`,
      );
    }

    const doc = await this.handleInputDescriptor(inputDescriptor);

    return new MDoc(
      [doc],
    );
  }

  private async handleInputDescriptor(id: InputDescriptor): Promise<DeviceSignedDocument> {
    const document = (this.mdoc.documents || []).find((d) => d.docType === id.id);
    if (!document) {
      // TODO; probl need to create a DocumentError here, but let's just throw for now
      throw new Error(`The mdoc does not have a document with DocType "${id.id}"`);
    }

    const nameSpaces = await this.prepareNamespaces(id, document);

    return new DeviceSignedDocument(
      document.docType,
      {
        nameSpaces,
        issuerAuth: document.issuerSigned.issuerAuth,
      },
      await this.getDeviceSigned(document.docType),
    );
  }

  private async getDeviceSigned(docType: string): Promise<DeviceSigned> {
    const sessionTranscript = [
      null, // deviceEngagementBytes
      null, // eReaderKeyBytes,
      this.handover,
    ];

    const deviceAuthenticationBytes = calculateDeviceAutenticationBytes(
      sessionTranscript,
      docType,
      this.nameSpaces,
    );

    const deviceSigned: DeviceSigned = {
      nameSpaces: this.nameSpaces,
      deviceAuth: this.useMac
        ? await this.getDeviceAuthMac(deviceAuthenticationBytes)
        : await this.getDeviceAuthSign(deviceAuthenticationBytes),
    };

    return deviceSigned;
  }

  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  private async getDeviceAuthMac(data: Uint8Array): Promise<DeviceAuth> {
    throw new Error('not implemented');
    // if (!this.devicePrivateKey) throw new Error('Missing devicePrivateKey');
    // if (!this.readerPublicKey) throw new Error('Missing readerPublicKey');

    // Mac0.create(
    //   { alg: 'HS256' },
    //   { kid: '11' },
    //   Buffer.from(data),
    //   this.devicePrivateKey,
    // );

    // // WIP Not implemented
    // // eslint-disable-next-line @typescript-eslint/no-unused-vars
    // const ephemeralPrivateKey = ''; // derived from this.devicePrivateKey
    // // eslint-disable-next-line @typescript-eslint/no-unused-vars
    // const ephemeralPublicKey = ''; // derived from this.readerPublicKey

    // return {
    //   deviceMac: 'todo',
    // };
  }

  private async getDeviceAuthSign(cborData: Uint8Array): Promise<DeviceAuth> {
    if (!this.devicePrivateKey) throw new Error('Missing devicePrivateKey');
    const key = await jose.importJWK(this.devicePrivateKey);
    const deviceSignature = await Sign1.sign(
      { alg: this.alg },
      { kid: this.devicePrivateKey.kid },
      Buffer.from(cborData),
      key,
    );
    return { deviceSignature };
  }

  private async prepareNamespaces(id: InputDescriptor, document: IssuerSignedDocument) {
    const requestedFields = id.constraints.fields;
    const nameSpaces: { [ns: string]: any } = {};
    for await (const field of requestedFields) {
      const result = await this.prepareDigest(field.path, document);
      if (!result) {
        // TODO: Do we add an entry to DocumentErrors if not found?
        console.log(`No matching field found for ${field.path}`);
        continue;
      }

      const { nameSpace, digest } = result;
      if (!nameSpaces[nameSpace]) nameSpaces[nameSpace] = [];
      nameSpaces[nameSpace].push(digest);
    }

    return nameSpaces;
  }

  private async prepareDigest(
    paths: string[],
    document: IssuerSignedDocument,
  ): Promise<{ nameSpace: string; digest: IssuerSignedItem } | null> {
    /**
     * path looks like this: "$['org.iso.18013.5.1']['family_name']"
     * the regex creates two groups with contents between "['" and "']"
     * the second entry in each group contains the result without the "'[" or "']"
     */
    for (const path of paths) {
      // eslint-disable-next-line @typescript-eslint/no-unused-vars
      const [[_1, nameSpace], [_2, elementIdentifier]] = [...path.matchAll(/\['(.*?)'\]/g)];
      if (!nameSpace) throw new Error(`Failed to parse namespace from path "${path}"`);
      if (!elementIdentifier) throw new Error(`Failed to parse elementIdentifier from path "${path}"`);

      const nsAttrs: IssuerSignedItem[] = document.issuerSigned.nameSpaces[nameSpace] || [];
      const digest = nsAttrs.find((d) => d.elementIdentifier === elementIdentifier);

      if (elementIdentifier.startsWith('age_over_')) {
        return this.handleAgeOverNN(elementIdentifier, nameSpace, nsAttrs);
      }

      if (digest) {
        return {
          nameSpace,
          digest,
        };
      }
    }

    return null;
  }

  private handleAgeOverNN(
    request: string,
    nameSpace: string,
    attributes: IssuerSignedItem[],
  ): { nameSpace: string; digest: IssuerSignedItem } | null {
    const ageOverList = attributes
      .map((a, i) => {
        const { elementIdentifier: key, elementValue: value } = a;
        return { key, value, index: i };
      })
      .filter((i) => i.key.startsWith('age_over_'))
      .map((i) => ({
        nn: parseInt(i.key.replace('age_over_', ''), 10),
        ...i,
      }))
      .sort((a, b) => a.nn - b.nn);

    const reqNN = parseInt(request.replace('age_over_', ''), 10);

    let item;
    // Find nearest TRUE
    item = ageOverList.filter((i) => i.value === true && i.nn >= reqNN)?.[0];

    if (!item) {
      // Find the nearest False
      item = ageOverList.sort((a, b) => b.nn - a.nn).filter((i) => i.value === false && i.nn <= reqNN)?.[0];
    }

    if (!item) {
      return null;
    }

    return {
      nameSpace,
      digest: attributes[item.index],
    };
  }
}
