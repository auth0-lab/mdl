/* eslint-disable max-classes-per-file */
export abstract class ValidatorResult {
  abstract isValid(): boolean;

  abstract getMessage(): string;
}

export class Valid extends ValidatorResult {
  // eslint-disable-next-line class-methods-use-this
  isValid(): boolean {
    return true;
  }

  // eslint-disable-next-line class-methods-use-this
  getMessage(): string {
    return '';
  }
}

export class ValidationError extends ValidatorResult {
  private readonly errorMessage: string;

  constructor(errorMessage: string) {
    super();
    this.errorMessage = errorMessage;
  }

  // eslint-disable-next-line class-methods-use-this
  isValid(): boolean {
    return false;
  }

  getMessage(): string {
    return this.errorMessage;
  }
}
