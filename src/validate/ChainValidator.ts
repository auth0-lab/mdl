import { Valid, ValidationError, ValidatorResult } from './ValidatorResult';
import AbstractValidator from './AbstractValidator';

class ChainValidator extends AbstractValidator {
  private validators: Array<AbstractValidator>;

  constructor(validators: Array<AbstractValidator>) {
    super();
    this.validators = validators;
  }

  validate(data: unknown): ValidatorResult {
    for (let i = 0; i < this.validators.length; i += 1) {
      const validationResult = this.validators[i].validate(data);

      if (validationResult instanceof ValidationError) {
        return validationResult;
      }
    }

    return new Valid();
  }
}

export default ChainValidator;
