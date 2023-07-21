import AbstractValidator from '../AbstractValidator';
import { ValidatorResult } from '../ValidatorResult';
import CoseSign1 from '../../cose/CoseSign1';

abstract class AbstractCoseValidator extends AbstractValidator {
  abstract validate(data: CoseSign1): ValidatorResult;
}

export default AbstractCoseValidator;
