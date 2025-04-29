import debug from 'debug';
import { MDLError } from './errors';

const log = debug('mdl');

export const VerificationAssessmentId = {
  ISSUER_AUTH: {
    IssuerCertificateValidity: 'ISSUER_CERTIFICATE_VALIDITY',
    IssuerSignatureValidity: 'ISSUER_SIGNATURE_VALIDITY',
    MsoSignedDateWithinCertificateValidity: 'MSO_SIGNED_DATE_WITHIN_CERTIFICATE_VALIDITY',
    MsoValidityAtVerificationTime: 'MSO_VALIDITY_AT_VERIFICATION_TIME',
    IssuerSubjectCountryNamePresence: 'ISSUER_SUBJECT_COUNTRY_NAME_PRESENCE',
  },

  DEVICE_AUTH: {
    DocumentDeviceSignaturePresence: 'DOCUMENT_DEVICE_SIGNATURE_PRESENCE',
    DeviceAuthSignatureOrMacPresence: 'DEVICE_AUTH_SIGNATURE_OR_MAC_PRESENCE',
    SessionTranscriptProvided: 'SESSION_TRANSCRIPT_PROVIDED',
    DeviceKeyAvailableInIssuerAuth: 'DEVICE_KEY_AVAILABLE_IN_ISSUERAUTH',
    DeviceSignatureValidity: 'DEVICE_SIGNATURE_VALIDITY',
    DeviceMacPresence: 'DEVICE_MAC_PRESENCE',
    DeviceMacAlgorithmCorrectness: 'DEVICE_MAC_ALGORITHM_CORRECTNESS',
    EphemeralKeyPresence: 'EPHEMERAL_KEY_PRESENCE',
    DeviceMacValidity: 'DEVICE_MAC_VALIDITY',
  },

  DATA_INTEGRITY: {
    IssuerAuthDigestAlgorithmSupported: 'ISSUER_AUTH_DIGEST_ALGORITHM_SUPPORTED',
    IssuerAuthNamespaceDigestPresence: 'ISSUER_AUTH_NAMESPACE_DIGEST_PRESENCE',
    AttributeDigestMatch: 'ATTRIBUTE_DIGEST_MATCH',
    IssuingCountryMatchesCertificate: 'ISSUING_COUNTRY_MATCHES_CERTIFICATE',
    IssuingJurisdictionMatchesCertificate: 'ISSUING_JURISDICTION_MATCHES_CERTIFICATE',
  },

  DOCUMENT_FORMAT: {
    DeviceResponseVersionPresence: 'DEVICE_RESPONSE_VERSION_PRESENCE',
    DeviceResponseVersionSupported: 'DEVICE_RESPONSE_VERSION_SUPPORTED',
    DeviceResponseDocumentPresence: 'DEVICE_RESPONSE_DOCUMENT_PRESENCE',
  },
} as const;

export type VerificationAssessment = {
  status: 'PASSED' | 'FAILED' | 'WARNING',
  check: string,
  reason?: string,
} & {
  [C in keyof typeof VerificationAssessmentId]: {
    category: C;
    id: typeof VerificationAssessmentId[C][keyof typeof VerificationAssessmentId[C]];
  };
}[keyof typeof VerificationAssessmentId];

export type VerificationCallback = (item: VerificationAssessment) => void;
export type UserDefinedVerificationCallback = (item: VerificationAssessment, original: VerificationCallback) => void;

export const defaultCallback: VerificationCallback = ((verification) => {
  log(`Verification: ${verification.check} => ${verification.status}`);
  if (verification.status !== 'FAILED') return;
  throw new MDLError(verification.reason ?? verification.check, verification.id);
});

export const buildCallback = (callback?: UserDefinedVerificationCallback): VerificationCallback => {
  if (typeof callback === 'undefined') { return defaultCallback; }
  return (item: VerificationAssessment) => {
    callback(item, defaultCallback);
  };
};

export const onCatCheck = <C extends keyof typeof VerificationAssessmentId>(onCheck: UserDefinedVerificationCallback, category: C) => {
  return (item: Omit<Extract<VerificationAssessment, { category: C }>, 'category'>) => {
    onCheck({ ...item, category } as VerificationAssessment, defaultCallback);
  };
};
