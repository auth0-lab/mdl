/** @type {import('ts-jest').JestConfigWithTsJest} */
module.exports = {
  preset: 'ts-jest',
  testEnvironment: 'node',
  transform: {
    '.*/__tests__/.*/.*\\.tests\\.ts': ['ts-jest', {isolatedModules: true}]
  },
  testMatch: ['**/__tests__/**/*.tests.ts'],
};
