import { CoseProtectedHeaders } from '../cose';
import headerFromMap from './headerFromMap';
import { cborDecode } from '../cbor';

const headerFromProtectedHeaders = (
  headers: CoseProtectedHeaders,
  key: number,
): unknown => {
  const map = cborDecode(headers);

  if (!(map instanceof Map)) {
    throw Error('Protected headers is not cbor encoded map');
  }

  return headerFromMap(map, key);
};

export default headerFromProtectedHeaders;
