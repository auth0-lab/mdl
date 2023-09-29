import { hex } from 'buffer-tag';
import fs from 'fs';

import { DeviceResponseVerifier } from '../../src/index';

export const ISSUER_CERTIFICATE = fs.readFileSync(
  `${__dirname}/issuer.pem`,
  'utf-8',
);

describe('example 4: device response with device attributes', () => {
  const ephemeralReaderKey = hex`534b526561646572`;
  const encodedSessionTranscript = hex`d818589e83f6f68466313233343536782b437131616e506238765a55356a354330643768637362754a4c4270496177554a4944515269324562776234785c687474703a2f2f6c6f63616c686f73743a343030302f6170692f70726573656e746174696f6e5f726571756573742f64633839393964662d643665612d346338342d393938352d3337613862383161383265632f63616c6c6261636b6761626364656667`;
  const deviceResponse = hex`b900036776657273696f6e63312e3069646f63756d656e747381b9000367646f6354797065756f72672e69736f2e31383031332e352e312e6d444c6c6973737565725369676e6564b900026a6e616d65537061636573b90001716f72672e69736f2e31383031332e352e318cd8185867b90004686469676573744944006672616e646f6d58203d382b0035ffb919b1cd6e511deaaa845e78abfa4f74502bd2894452d70b589671656c656d656e744964656e7469666965726b66616d696c795f6e616d656c656c656d656e7456616c756565536d697468d8185865b90004686469676573744944016672616e646f6d582011da9772a5332e54ceb4140a97baa35e85c77760891a741122fbdca97f46315771656c656d656e744964656e7469666965726a676976656e5f6e616d656c656c656d656e7456616c7565644a6f686ed818586eb90004686469676573744944026672616e646f6d5820e9bb72564e897bf41e7bdb59de6f14e4e44b3d380a1df937247622bc72f36b8a71656c656d656e744964656e7469666965726a62697274685f646174656c656c656d656e7456616c7565d903ec6a313938302d30362d3135d818586eb90004686469676573744944036672616e646f6d58204a4ffbac2c1f26818b743257c3a6b21788e24ce98bb75ede59faf48756dc154471656c656d656e744964656e7469666965726a69737375655f646174656c656c656d656e7456616c7565d903ec6a323032332d30332d3031d818586fb90004686469676573744944046672616e646f6d5820ad0bc45bfdc67d347b74af45aad7849898718d270911aba22adb25772d0f512f71656c656d656e744964656e7469666965726b6578706972795f646174656c656c656d656e7456616c7565d903ec6a323032382d30332d3331d8185868b90004686469676573744944056672616e646f6d5820a3634fa5da0d398ec71cec99a4d7c5aa24d26b0fc4ee5346e9d61639e11a358771656c656d656e744964656e7469666965726f69737375696e675f636f756e7472796c656c656d656e7456616c7565625553d818586eb90004686469676573744944066672616e646f6d5820c574e015c58d63f6274a3925eab31f6b12f501f288a987ebb2e207e8a9686a9071656c656d656e744964656e7469666965727169737375696e675f617574686f726974796c656c656d656e7456616c7565664e5920444d56d8185873b90004686469676573744944076672616e646f6d58205b1163027cae36710ec73b3829bfe28193347d53419d41f5d09bff1eb93cd72871656c656d656e744964656e7469666965727469737375696e675f6a7572697364696374696f6e6c656c656d656e7456616c7565684e657720596f726bd8185871b90004686469676573744944086672616e646f6d5820937623125862b2135d8a9c2e0cada8e4c42e14591ce623109d8e39a6dc0331d571656c656d656e744964656e7469666965726f646f63756d656e745f6e756d6265726c656c656d656e7456616c75656b30312d3333332d37303730d8185863b90004686469676573744944096672616e646f6d5820941bb3b78a355a5678019fe2088e5bd7b715f6208d61d05d078290533693f01e71656c656d656e744964656e74696669657268706f7274726169746c656c656d656e7456616c75656462737472d81858b1b900046864696765737449440a6672616e646f6d5820934b34b4d8c82e44b1ddb0a937740f56f8ac1e39cc480946bd169015b9f38c9371656c656d656e744964656e7469666965727264726976696e675f70726976696c656765736c656c656d656e7456616c756581b900037576656869636c655f63617465676f72795f636f646561436a69737375655f646174656a323032332d30332d30316b6578706972795f646174656a323032382d30332d3331d818587ab900046864696765737449440b6672616e646f6d58203a76b962b891a01bd2c1351dbe0c30f91b53e3e6c55642d646de15f603bb024171656c656d656e744964656e74696669657276756e5f64697374696e6775697368696e675f7369676e6c656c656d656e7456616c75656d7462642d75732e6e792e646d766a697373756572417574688443a10126a20442313118218159022e3082022a308201d0a003020102021457c6ccd308bde43eca3744f2a87138dabbb884e8300a06082a8648ce3d0403023053310b30090603550406130255533111300f06035504080c084e657720596f726b310f300d06035504070c06416c62616e79310f300d060355040a0c064e5920444d56310f300d060355040b0c064e5920444d56301e170d3233303931343134353531385a170d3333303931313134353531385a3053310b30090603550406130255533111300f06035504080c084e657720596f726b310f300d06035504070c06416c62616e79310f300d060355040a0c064e5920444d56310f300d060355040b0c064e5920444d563059301306072a8648ce3d020106082a8648ce3d03010703420004893c2d8347906dc6cd69b7f636af4bfd533f96184f0aadacd10830da4471dbdb60ac170d1cfc534fae2d9dcd488f7747fdf978d925ea31e9e9083c382ba9ed53a38181307f301d0603551d0e04160414ab6d2e03b91d492240338fbccadefd9333eaf6c7301f0603551d23041830168014ab6d2e03b91d492240338fbccadefd9333eaf6c7300f0603551d130101ff040530030101ff302c06096086480186f842010d041f161d4f70656e53534c2047656e657261746564204365727469666963617465300a06082a8648ce3d0403020348003045022009fd0cab97b03e78f64e74d7dcee88668c476a0afc5aa2cebffe07d3be772ea9022100da38abc98a080f49f24ffece1fffc8a6cdd5b2c0b5da8fc7b767ac3a95dcb83e590319d818590314b900066776657273696f6e63312e306f646967657374416c676f726974686d675348412d3235366c76616c756544696765737473b900026f6f72672e637573746f6d2e74657374a10058204cdeb0a8bad523598952584739ce9dcebd76811847fa58836f7a3662764874b6716f72672e69736f2e31383031332e352e31ac00582050da04ab2d084569625b617e4da11cfd785a5e0957a37c2245a38c449a96404101582063c6bacdc365c332238d01e18ea0398bfbe8447114251cf5a38a7f1cea21d3fa0258203d2c74ba23ea297c52a954e2a892e170c2a0c26294a318eb7dbd105526a03c3b0358209237ad732db0020af89c80a89b8c770e73cff2afb9a0093a91ba6a6099a4f7750458206227a459e9dbceed6df9015120b61f1c38aaf6c43cea4435f4a87c0e7e343a73055820427a4ebabb78d89bf0488d4b44c8b5e945d6c6c9662e4a11b447ce7933d326680658204726344aabcf8e64b46ee905363805fe98d7bd17af3a7522a54aac5331ffd703075820e8edf231b7a3ad52939f230d830dd5c8f2791f944a054f9aeb15a28e30090b2b085820bf1c01e1b4af286a44082ea0fa092cc9f1eb6b19e78b83f18f37f85bb48f5792095820cf10644f20806c5ef0c4aa5f08496e4e6ab8752b713fa6f65664d911536092990a58204c6bff3c68bcd61e7d204f8dfd9bd378e1663162ad18cd8a5101527d2dccc30c0b5820b6902126d95e8238827bcca0aa8c1e011bdb56ce743dcd09217c3088eb2426016d6465766963654b6579496e666fb90001696465766963654b6579a40102215820881879ca7a238b19bf0f4c1f8c00e9a2e19ba7a6f73eae92b851d4de1b508559225820a314b538039127b5cd50735f54519e33c134450545c5603ad9f263facc56d377200167646f6354797065756f72672e69736f2e31383031332e352e312e6d444c6c76616c6964697479496e666fb90003667369676e6564c074323032332d30392d32395431353a30363a32305a6976616c696446726f6dc074323032332d30392d32395431353a30363a32305a6a76616c6964556e74696cc074323037332d30392d32395431353a30363a32305a5840a46fee0aecec72dd699babd2a2e4ed3c25c655d9bd0e79f1849d0ee64d03cd3a253e005acb48faa2cd05f46c59525ce6de612cc7cc4aecbd6ccd72397a7507d86c6465766963655369676e6564b900026a6e616d65537061636573d818583aa1726f72672e69736f2e77616c6c65742e6d444ca26776657273696f6e016a6465766963654e616d65706d444c2053757065722057616c6c65746a64657669636541757468b900016f6465766963655369676e61747572658443a10126a10442313159010dd818590108847444657669636541757468656e7469636174696f6e83f6f68466313233343536782b437131616e506238765a55356a354330643768637362754a4c4270496177554a4944515269324562776234785c687474703a2f2f6c6f63616c686f73743a343030302f6170692f70726573656e746174696f6e5f726571756573742f64633839393964662d643665612d346338342d393938352d3337613862383161383265632f63616c6c6261636b6761626364656667756f72672e69736f2e31383031332e352e312e6d444cd818583aa1726f72672e69736f2e77616c6c65742e6d444ca26776657273696f6e016a6465766963654e616d65706d444c2053757065722057616c6c657458404119c75ea0fbd87041b7a01dfe3c9808888d7335c6ffedbc56f5133cb3a9b04da8e29ec0326e954df0dcd53aee2ea84fa8b820a06d2cfb510ff61eed39ecb1536673746174757300`;
  const verifier = new DeviceResponseVerifier([ISSUER_CERTIFICATE]);

  it('should verify properly', async () => {
    await verifier.verify(deviceResponse, {
      ephemeralReaderKey,
      encodedSessionTranscript,
    });
  });

  it('should get the right diagnostic info', async () => {
    const diagnostic = await verifier.getDiagnosticInformation(deviceResponse, {
      ephemeralReaderKey,
      encodedSessionTranscript,
    });
    expect(diagnostic).toMatchSnapshot();
  });
});