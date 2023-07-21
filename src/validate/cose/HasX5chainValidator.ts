import { Valid, ValidationError, ValidatorResult } from '../ValidatorResult';
import AbstractCoseValidator from './AbstractCoseValidator';
import CoseSign1 from '../../cose/CoseSign1';
import { extractX5Chain } from '../../cose/header/headers';

class HasX5chainValidator extends AbstractCoseValidator {
  validate(msg: CoseSign1): ValidatorResult {
    let x5chain = '';

    try {
      x5chain = extractX5Chain(msg.getUnprotectedHeaders());
    } catch (error) {
      return new ValidationError('x5chain not set in the unprotected headers');
    }

    if (x5chain.length === 0) {
      return new ValidationError('x5chain is empty');
    }

    return new Valid();
  }
}

export default HasX5chainValidator;
