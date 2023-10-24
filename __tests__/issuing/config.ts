//  All the keys here are randomly generated for the purpose of this test.

export const DEVICE_JWK = {
  kty: 'EC',
  x: 'iBh5ynojixm_D0wfjADpouGbp6b3Pq6SuFHU3htQhVk',
  y: 'oxS1OAORJ7XNUHNfVFGeM8E0RQVFxWA62fJj-sxW03c',
  crv: 'P-256',
  d: 'eRpAZr3eV5xMMnPG3kWjg90Y-bBff9LqmlQuk49HUtA',
};

export const ISSUER_CERTIFICATE = `-----BEGIN CERTIFICATE-----
MIICKjCCAdCgAwIBAgIUV8bM0wi95D7KN0TyqHE42ru4hOgwCgYIKoZIzj0EAwIw
UzELMAkGA1UEBhMCVVMxETAPBgNVBAgMCE5ldyBZb3JrMQ8wDQYDVQQHDAZBbGJh
bnkxDzANBgNVBAoMBk5ZIERNVjEPMA0GA1UECwwGTlkgRE1WMB4XDTIzMDkxNDE0
NTUxOFoXDTMzMDkxMTE0NTUxOFowUzELMAkGA1UEBhMCVVMxETAPBgNVBAgMCE5l
dyBZb3JrMQ8wDQYDVQQHDAZBbGJhbnkxDzANBgNVBAoMBk5ZIERNVjEPMA0GA1UE
CwwGTlkgRE1WMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEiTwtg0eQbcbNabf2
Nq9L/VM/lhhPCq2s0Qgw2kRx29tgrBcNHPxTT64tnc1Ij3dH/fl42SXqMenpCDw4
K6ntU6OBgTB/MB0GA1UdDgQWBBSrbS4DuR1JIkAzj7zK3v2TM+r2xzAfBgNVHSME
GDAWgBSrbS4DuR1JIkAzj7zK3v2TM+r2xzAPBgNVHRMBAf8EBTADAQH/MCwGCWCG
SAGG+EIBDQQfFh1PcGVuU1NMIEdlbmVyYXRlZCBDZXJ0aWZpY2F0ZTAKBggqhkjO
PQQDAgNIADBFAiAJ/Qyrl7A+ePZOdNfc7ohmjEdqCvxaos6//gfTvncuqQIhANo4
q8mKCA9J8k/+zh//yKbN1bLAtdqPx7dnrDqV3Lg+
-----END CERTIFICATE-----`;

export const ISSUER_CERTIFICATE_PRIVATE_KEY = `-----BEGIN PRIVATE KEY-----
MEECAQAwEwYHKoZIzj0CAQYIKoZIzj0DAQcEJzAlAgEBBCCjo+vMGbV0J9LCokdb
oNWqYk4JBIgCiysI99sUkMw2ng==
-----END PRIVATE KEY-----`;

export const PRESENTATION_DEFINITION_1 = {
  id: 'mdl-test-all-data',
  input_descriptors: [
    {
      id: 'org.iso.18013.5.1.mDL',
      format: {
        mso_mdoc: {
          alg: ['EdDSA', 'ES256'],
        },
      },
      constraints: {
        limit_disclosure: 'required',
        fields: [
          {
            path: ["$['org.iso.18013.5.1']['family_name']"],
            intent_to_retain: false,
          },
          {
            path: ["$['org.iso.18013.5.1']['given_name']"],
            intent_to_retain: false,
          },
          {
            path: ["$['org.iso.18013.5.1']['birth_date']"],
            intent_to_retain: false,
          },
          {
            path: ["$['org.iso.18013.5.1']['issue_date']"],
            intent_to_retain: false,
          },
          {
            path: ["$['org.iso.18013.5.1']['expiry_date']"],
            intent_to_retain: false,
          },
          {
            path: ["$['org.iso.18013.5.1']['issuing_country']"],
            intent_to_retain: false,
          },
          {
            path: ["$['org.iso.18013.5.1']['issuing_authority']"],
            intent_to_retain: false,
          },
          {
            path: ["$['org.iso.18013.5.1']['issuing_jurisdiction']"],
            intent_to_retain: false,
          },
          {
            path: ["$['org.iso.18013.5.1']['document_number']"],
            intent_to_retain: false,
          },
          {
            path: ["$['org.iso.18013.5.1']['portrait']"],
            intent_to_retain: false,
          },
          {
            path: ["$['org.iso.18013.5.1']['driving_privileges']"],
            intent_to_retain: false,
          },
          {
            path: ["$['org.iso.18013.5.1']['un_distinguishing_sign']"],
            intent_to_retain: false,
          },
        ],
      },
    },
  ],
};

export const PRESENTATION_DEFINITION_2 = {
  id: 'mdl-test-age-over-18',
  input_descriptors: [
    {
      id: 'org.iso.18013.5.1.mDL',
      format: {
        mso_mdoc: {
          alg: ['EdDSA', 'ES256'],
        },
      },
      constraints: {
        limit_disclosure: 'required',
        fields: [
          {
            path: ["$['org.iso.18013.5.1']['age_over_18']"],
            intent_to_retain: false,
          },
        ],
      },
    },
  ],
};
