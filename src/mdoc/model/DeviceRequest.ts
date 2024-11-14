export type PresentationDefinitionField = {
  path: string[];
  intent_to_retain: boolean;
}

export type Format = {
  mso_mdoc: {
    alg: string[];
  };
};

export type InputDescriptor = {
  id: string;
  format: Format;
  constraints: {
    limit_disclosure: string;
    fields: PresentationDefinitionField[]
  }
};

export type DeviceRequest = {
  version: '1.1'
  docRequests: DocRequest[];
  /**
   * List of MAC Keys from the reader, one per supported curve.
   * Optional field.
   */
  macKeys?: Buffer[];
};

export type DocRequest = {
  
}
