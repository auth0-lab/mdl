const headerFromMap = (
  map: Map<number, unknown>,
  key: number,
): unknown => {
  if (!map.has(key)) {
    throw new Error(`Map doesn't have key ${key}`);
  }

  return map.get(key);
};

export default headerFromMap;
