import * as jose from 'jose';
import { Sign1 } from 'cose-kit';
import { InputDescriptor, PresentationDefinition } from './PresentationDefinition';
import { MDoc } from './MDoc';
import { DeviceAuth, DeviceSigned } from './types';
import { DeviceSignedDocument, IssuerSignedDocument } from './IssuerSignedDocument';
import { IssuerSignedItem } from '../IssuerSignedItem';
import { DataItem, cborEncode } from '../../cbor';
import { parse } from '../parser';

const DOC_TYPE = 'org.iso.18013.5.1.mDL';

export class DeviceResponse {
  private mdoc: MDoc;
  private pd: PresentationDefinition;
  private handover: string[];
  private useMac = true;
  private devicePrivateKey: jose.KeyLike;
  private readerPublicKey: jose.KeyLike;
  public deviceResponseCbor: Buffer;
  public nameSpaces: Map<string, Map<string, any>> = new Map();

  public static from(mdoc: MDoc | Uint8Array) {
    if (mdoc instanceof Uint8Array) {
      return new DeviceResponse(parse(mdoc));
    }
    return new DeviceResponse(mdoc);
  }

  constructor(mdoc: MDoc) {
    this.mdoc = mdoc;
  }

  public usingPresentationDefinition(pd: PresentationDefinition) {
    this.pd = pd;
    return this;
  }

  public usingHandover(handover: string[]) {
    this.handover = handover;
    return this;
  }

  public addDeviceNameSpace(nameSpace: string, data: Record<string, any>) {
    this.nameSpaces.set(nameSpace, new Map(Object.entries(data)));
    return this;
  }

  public authenticateWithSignature(devicePrivateKey: jose.KeyLike) {
    this.devicePrivateKey = devicePrivateKey;
    this.useMac = false;
    return this;
  }

  public async generate(): Promise<MDoc> {
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
      await this.getdeviceSigned(document.docType),
    );
  }

  private async getdeviceSigned(docType: string): Promise<DeviceSigned> {
    const sessionTranscript = [
      null, // deviceEngagementBytes
      null, // eReaderKeyBytes,
      this.handover,
    ];
    const nameSpaces = DataItem.fromData(this.nameSpaces);

    const deviceAuthentication = [
      'DeviceAuthentication',
      sessionTranscript,
      docType,
      nameSpaces,
    ];

    const deviceAuthenticationBytes = cborEncode(DataItem.fromData(deviceAuthentication));

    const deviceSigned: DeviceSigned = {
      nameSpaces: this.nameSpaces,
      deviceAuth: this.useMac
        ? await this.getDeviceAuthMac(deviceAuthenticationBytes)
        : await this.getDeviceAuthSign(deviceAuthenticationBytes),
    };

    return deviceSigned;
  }

  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  private async getDeviceAuthMac(data: Buffer): Promise<DeviceAuth> {
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

  private async getDeviceAuthSign(cborData: Buffer | Uint8Array): Promise<DeviceAuth> {
    if (!this.devicePrivateKey) throw new Error('Missing devicePrivateKey');

    const deviceSignature = await Sign1.sign(
      { alg: 'ES256' },
      { kid: '11' },
      Buffer.from(cborData),
      this.devicePrivateKey,
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

  /**
   * path looks like this: "$['org.iso.18013.5.1']['family_name']"
   * the regex creates two groups with contents between "['" and "']"
   * the second entry in each group contains the result without the "'[" or "']"
   */
  private async prepareDigest(
    paths: string[],
    document: IssuerSignedDocument,
  ): Promise<{ nameSpace: string; digest: IssuerSignedItem } | null> {
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
