import * as jose from 'jose';
import { COSEKeyFromJWK, COSEKeyToJWK, Mac0, Sign1, importCOSEKey } from 'cose-kit';
import { Buffer } from 'buffer';
import { InputDescriptor, PresentationDefinition } from './PresentationDefinition';
import { MDoc } from './MDoc';
import { DeviceAuth, DeviceSigned, MacSupportedAlgs, SupportedAlgs } from './types';
import { IssuerSignedDocument } from './IssuerSignedDocument';
import { DeviceSignedDocument } from './DeviceSignedDocument';
import { IssuerSignedItem } from '../IssuerSignedItem';
import { parse } from '../parser';
import { calculateDeviceAutenticationBytes, calculateEphemeralMacKey } from '../utils';
import { DataItem, cborEncode } from '../../cbor';
import COSEKeyToRAW from '../../cose/coseKey';

/**
 * A builder class for creating a device response.
 */
export class DeviceResponse {
  private mdoc: MDoc;
  private pd: PresentationDefinition;
  private sessionTranscriptBytes: Buffer;
  private useMac = true;
  private devicePrivateKey: Uint8Array;
  public deviceResponseCbor: Buffer;
  public nameSpaces: Record<string, Record<string, any>> = {};
  private alg: SupportedAlgs;
  private macAlg: MacSupportedAlgs;
  private ephemeralPublicKey: Uint8Array;

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
    if (!pd.input_descriptors.length) {
      throw new Error('The Presentation Definition must have at least one Input Descriptor object.');
    }

    const hasDuplicates = pd.input_descriptors.some((id1, idx) => pd.input_descriptors.findIndex((id2) => id2.id === id1.id) !== idx);
    if (hasDuplicates) {
      throw new Error('Each Input Descriptor object must have a unique id property.');
    }

    this.pd = pd;
    return this;
  }

  /**
   * Set the session transcript data to use for the device response with the given handover data.
   * this is a shortcut to calling `usingSessionTranscriptBytes(<cbor encoding of [null, null, handover] in a Tagged 24 structure>)`,
   * which is what the OID4VP protocol expects.
   *
   * @param {string[]} handover - The handover data to use in the session transcript.
   * @returns {DeviceResponse}
   */
  public usingHandover(handover: string[]): DeviceResponse {
    this.usingSessionTranscriptBytes(cborEncode(DataItem.fromData([null, null, handover])));
    return this;
  }

  /**
   * Set the session transcript data to use for the device response. This is arbitrary and should match
   * the session transcript as it will be calculated by the verifier.
   * We expect a buffer of bytes, as defined in as defined in ISO/IEC 18013-7 in both Annex A (Web API) and Annex B (OID4VP)
   * @param {Buffer} sessionTranscriptBytes - The sessionTranscriptBytes data to use in the session transcript.
   * @returns {DeviceResponse}
   */
  public usingSessionTranscriptBytes(sessionTranscriptBytes: Buffer): DeviceResponse {
    if (this.sessionTranscriptBytes) {
      throw new Error('A session transcript has already been set, either with .usingHandover or .usingSessionTranscriptBytes');
    }
    this.sessionTranscriptBytes = sessionTranscriptBytes;
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
      this.devicePrivateKey = devicePrivateKey;
    } else {
      this.devicePrivateKey = COSEKeyFromJWK(devicePrivateKey);
    }
    this.alg = alg;
    this.useMac = false;
    return this;
  }

  /**
   * Set the reader shared key to be used for signing the device response with MAC.
   *
   * @param  {jose.JWK | Uint8Array} devicePrivateKey - The device's private key either as a JWK or a COSEKey.
   * @param  {Uint8Array} ephemeralPublicKey - The public part of the ephemeral key generated by the MDOC.
   * @param  {SupportedAlgs} alg - The algorithm to use for signing the device response.
   * @returns {DeviceResponse}
   */
  public authenticateWithMAC(
    devicePrivateKey: jose.JWK | Uint8Array,
    ephemeralPublicKey: Uint8Array,
    alg: MacSupportedAlgs,
  ): DeviceResponse {
    if (devicePrivateKey instanceof Uint8Array) {
      this.devicePrivateKey = devicePrivateKey;
    } else {
      this.devicePrivateKey = COSEKeyFromJWK(devicePrivateKey);
    }
    this.ephemeralPublicKey = ephemeralPublicKey;
    this.macAlg = alg;
    this.useMac = true;
    return this;
  }

  /**
   * Sign the device response and return the MDoc.
   *
   * @returns {Promise<MDoc>} - The device response as an MDoc.
   */
  public async sign(): Promise<MDoc> {
    if (!this.pd) throw new Error('Must provide a presentation definition with .usingPresentationDefinition()');
    if (!this.sessionTranscriptBytes) throw new Error('Must provide the session transcript with .usingHandover() or .usingSessionTranscriptBytes()');

    const docs = await Promise.all(this.pd.input_descriptors.map((id) => this.handleInputDescriptor(id)));
    return new MDoc(docs);
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
    const deviceAuthenticationBytes = calculateDeviceAutenticationBytes(
      this.sessionTranscriptBytes,
      docType,
      this.nameSpaces,
    );

    const deviceSigned: DeviceSigned = {
      nameSpaces: this.nameSpaces,
      deviceAuth: this.useMac
        ? await this.getDeviceAuthMac(deviceAuthenticationBytes, this.sessionTranscriptBytes)
        : await this.getDeviceAuthSign(deviceAuthenticationBytes),
    };

    return deviceSigned;
  }

  private async getDeviceAuthMac(
    deviceAuthenticationBytes: Uint8Array,
    sessionTranscriptBytes: any,
  ): Promise<DeviceAuth> {
    const key = COSEKeyToRAW(this.devicePrivateKey);
    const { kid } = COSEKeyToJWK(this.devicePrivateKey);

    const ephemeralMacKey = await calculateEphemeralMacKey(
      key,
      this.ephemeralPublicKey,
      sessionTranscriptBytes,
    );

    const mac = await Mac0.create(
      { alg: this.macAlg },
      { kid },
      deviceAuthenticationBytes,
      ephemeralMacKey,
    );

    return { deviceMac: mac };
  }

  private async getDeviceAuthSign(cborData: Uint8Array): Promise<DeviceAuth> {
    if (!this.devicePrivateKey) throw new Error('Missing devicePrivateKey');
    const key = await importCOSEKey(this.devicePrivateKey);
    const { kid } = COSEKeyToJWK(this.devicePrivateKey);

    const deviceSignature = await Sign1.sign(
      { alg: this.alg },
      { kid },
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
