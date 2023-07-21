import { Valid, ValidationError, ValidatorResult } from '../ValidatorResult';
import AbstractCoseValidator from './AbstractCoseValidator';
import CoseSign1 from '../../cose/CoseSign1';
import { extractAlgorithm } from '../../cose/header/headers';

class KnownAlgorithmValidator extends AbstractCoseValidator {
  supportedAlgs: number[];

  constructor(supportedAlgs: number[]) {
    super();
    this.supportedAlgs = supportedAlgs;
  }

  validate(msg: CoseSign1): ValidatorResult {
    let alg: number;
    try {
      alg = extractAlgorithm(msg.getProtectedHeaders());
    } catch (error) {
      return new ValidationError('Algorithm not set in the protected headers');
    }

    if (!this.supportedAlgs.includes(alg)) {
      return new ValidationError(
        `Algorithm is not supported. Expected: ${this.supportedAlgs.join(', ')}`,
      );
    }

    return new Valid();
  }
}

export default KnownAlgorithmValidator;
