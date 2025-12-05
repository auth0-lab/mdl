export type DcqlQuery = {
  credentials: DcqlQueryCredential[];
  credential_sets?: DcqlCredentialSetQuery[];
};

export type DcqlQueryCredential = {
  id: string;
  format: string;
  multiple?: boolean;
  meta: {
    vct_values?: string[];
    doctype_value?: string;
  };
  trusted_authorities?: any;
  require_cryptographic_holder_binding?: boolean;
  claims: DcqlClaim[];
  claim_sets?: string[][];
};

export type DcqlCredentialSetQuery = {
  options: string[][];
  required?: boolean;
};

export type DcqlClaim = {
  id: string;
  path: string[];
  values?: (string | number | boolean)[];
  intent_to_retain?: boolean;
};


