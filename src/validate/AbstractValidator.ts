import { ValidatorResult } from './ValidatorResult';

abstract class AbstractValidator {
  // eslint-disable-next-line no-unused-vars
  abstract validate(data: unknown): ValidatorResult;
}

export default AbstractValidator;
