import { hex } from 'buffer-tag';
import fs from 'fs';

import { DeviceResponseVerifier } from '../../src/index';

export const ISSUER_CERTIFICATE = fs.readFileSync(
  `${__dirname}/issuer.pem`,
  'utf-8',
);

describe('example 2: valid device response with partial disclosure', () => {
  const ephemeralReaderKey = hex`534b526561646572`;
  const encodedSessionTranscript = hex`d818589e83f6f68466313233343536782b437131616e506238765a55356a354330643768637362754a4c4270496177554a4944515269324562776234785c687474703a2f2f6c6f63616c686f73743a343030302f6170692f70726573656e746174696f6e5f726571756573742f64633839393964662d643665612d346338342d393938352d3337613862383161383265632f63616c6c6261636b6761626364656667`;
  const deviceResponse = hex`b900036776657273696f6e63312e3069646f63756d656e747381b9000367646f6354797065756f72672e69736f2e31383031332e352e312e6d444c6c6973737565725369676e6564b900026a6e616d65537061636573b90001716f72672e69736f2e31383031332e352e3186d8185867b90004686469676573744944006672616e646f6d5820caf54ce57929bf1ed0aef6a861ece552158bb0aa440f6b4f5eeee27fab72bd1871656c656d656e744964656e7469666965726b66616d696c795f6e616d656c656c656d656e7456616c756565536d697468d8185865b90004686469676573744944016672616e646f6d58201176fe7a0dd3b0c92855be06ac0c4454cee4e244729be08b8b2c740226a2fbf271656c656d656e744964656e7469666965726a676976656e5f6e616d656c656c656d656e7456616c7565644a6f686ed818586eb90004686469676573744944026672616e646f6d5820faf3deb9a86d7d6d6939bac2981b9d61e4afd11b9f754a920516b9049958093c71656c656d656e744964656e7469666965726a62697274685f646174656c656c656d656e7456616c7565d903ec6a313938302d30362d3135d8185868b90004686469676573744944056672616e646f6d58206c6c623a68ef8644c6e7fc8dec99f5b2273f097b906c2a698649672e1d5bf46371656c656d656e744964656e7469666965726f69737375696e675f636f756e7472796c656c656d656e7456616c7565625553d818586eb90004686469676573744944066672616e646f6d582075a3571a85aaef856abf156204ab5e61b6157e094c8c46361ab85e574717219671656c656d656e744964656e7469666965727169737375696e675f617574686f726974796c656c656d656e7456616c7565664e5920444d56d8185873b90004686469676573744944076672616e646f6d58208d1e9476763247e00f5c32407002d5cd06708b116d9bc5ba86dfbfb9b264d6ef71656c656d656e744964656e7469666965727469737375696e675f6a7572697364696374696f6e6c656c656d656e7456616c7565684e657720596f726b6a697373756572417574688443a10126a20442313118218159022e3082022a308201d0a003020102021457c6ccd308bde43eca3744f2a87138dabbb884e8300a06082a8648ce3d0403023053310b30090603550406130255533111300f06035504080c084e657720596f726b310f300d06035504070c06416c62616e79310f300d060355040a0c064e5920444d56310f300d060355040b0c064e5920444d56301e170d3233303931343134353531385a170d3333303931313134353531385a3053310b30090603550406130255533111300f06035504080c084e657720596f726b310f300d06035504070c06416c62616e79310f300d060355040a0c064e5920444d56310f300d060355040b0c064e5920444d563059301306072a8648ce3d020106082a8648ce3d03010703420004893c2d8347906dc6cd69b7f636af4bfd533f96184f0aadacd10830da4471dbdb60ac170d1cfc534fae2d9dcd488f7747fdf978d925ea31e9e9083c382ba9ed53a38181307f301d0603551d0e04160414ab6d2e03b91d492240338fbccadefd9333eaf6c7301f0603551d23041830168014ab6d2e03b91d492240338fbccadefd9333eaf6c7300f0603551d130101ff040530030101ff302c06096086480186f842010d041f161d4f70656e53534c2047656e657261746564204365727469666963617465300a06082a8648ce3d0403020348003045022009fd0cab97b03e78f64e74d7dcee88668c476a0afc5aa2cebffe07d3be772ea9022100da38abc98a080f49f24ffece1fffc8a6cdd5b2c0b5da8fc7b767ac3a95dcb83e590319d818590314b900066776657273696f6e63312e306f646967657374416c676f726974686d675348412d3235366c76616c756544696765737473b900026f6f72672e637573746f6d2e74657374a1005820522b5bdfa3da432224bc08371e99e18c9f2a050731d6715d68ae78ceece6b331716f72672e69736f2e31383031332e352e31ac0058205f77a19004624b6b457b5965d5b2e3f6dc52e0f99f8f7320cb97ccf1b460dfa5015820f8094183d02ff72eab21a66803c3d45ce2d357716b1972c2f000ee6d7d5b6c80025820d9b546635fc09227761912f5a8d0efe3097f1b12c11192b32a1893921fc60a4d03582078748809159aca7c3ad5b1651ceed55e1aef3f8564b16a37698e7e776733f1d90458200d2d4f3705b5c0f041b103b51a0518a09091bdf9b9944e0f58949f2436c91c2a055820afed30af6e2ff7a5b97034df439a8d4528481347b8e0f5dc2dcb26548100a756065820ec2857994ebe57b4badc5da68692b46e22a9a607c65ce938b2a1f96373ada60b07582043f80ae6ba7e54fd6e4045172256d2a9af3e3ba9833c93bf68830001b1cd1cfe0858209d1941ba0d8b4d094649335e5cc425bc38cf92352e085b095e6233971086798109582008dcfffb2db4236c2f43dd3fcd50ec562a1873b74a7e398cfd017ea6b16653bd0a58208393f56abb4e3705d5c57cf32034608b018aabfdaac0790f75755da99f9d94a20b5820aa02cf53c7563037542717a2578492d38ff9dce7994aa747e916b9d6bbc54d966d6465766963654b6579496e666fb90001696465766963654b6579a40102215820881879ca7a238b19bf0f4c1f8c00e9a2e19ba7a6f73eae92b851d4de1b508559225820a314b538039127b5cd50735f54519e33c134450545c5603ad9f263facc56d377200167646f6354797065756f72672e69736f2e31383031332e352e312e6d444c6c76616c6964697479496e666fb90003667369676e6564c074323032332d30392d32375431323a34383a34355a6976616c696446726f6dc074323032332d30392d32375431323a34383a34355a6a76616c6964556e74696cc074323037332d30392d32375431323a34383a34355a5840bffdb8888376539d2372e2cd16423a62400eadd70171427b71140f644e1cea174beefd770d30397afc4215cd34d8a6b3dfe9e3c5436322b95259674aaf3e4fd36c6465766963655369676e6564b900026a6e616d65537061636573d81843b900006a64657669636541757468b900016f6465766963655369676e61747572658443a10126a10442313158d4d81858d0847444657669636541757468656e7469636174696f6e83f6f68466313233343536782b437131616e506238765a55356a354330643768637362754a4c4270496177554a4944515269324562776234785c687474703a2f2f6c6f63616c686f73743a343030302f6170692f70726573656e746174696f6e5f726571756573742f64633839393964662d643665612d346338342d393938352d3337613862383161383265632f63616c6c6261636b6761626364656667756f72672e69736f2e31383031332e352e312e6d444cd81843b900005840a5d1c05155eb8a9e10b9497cd10c374e1532457a3ec78b9876a0f2fa00842cfbcbda77e9e394dcf5cfe598297ef9f513f2a10ea6f30558ad3cd0b3384a642ee76673746174757300`;
  const verifier = new DeviceResponseVerifier([ISSUER_CERTIFICATE]);

  it('should verify properly', async () => {
    await verifier.verify(deviceResponse, {
      ephemeralReaderKey,
      encodedSessionTranscript,
    });
  });

  it('should be able to verify without ephemeralReaderKey and encodedSessionTrasncript', async () => {
    await verifier.verify(deviceResponse, {
      onCheck: (verification, original) => {
        if (verification.category === 'DEVICE_AUTH') {
          return;
        }
        original(verification);
      },
    });
  });

  it('should contain only the disclosed fields', async () => {
    const { documents } = await verifier.verify(deviceResponse, {
      ephemeralReaderKey,
      encodedSessionTranscript,
    });

    const numberOfAttributes = documents[0]
      .issuerSigned
      .nameSpaces['org.iso.18013.5.1']
      .length;

    expect(numberOfAttributes).toBe(6);
  });

  it('should validate the digest of all fields', async () => {
    const { documents } = await verifier.verify(deviceResponse, {
      ephemeralReaderKey,
      encodedSessionTranscript,
    });

    const allFieldsAreValid = (await Promise.all(documents[0]
      .issuerSigned
      .nameSpaces['org.iso.18013.5.1']
      .map((field) => field.isValid()))).every(Boolean);

    expect(allFieldsAreValid).toBe(true);
  });
});
