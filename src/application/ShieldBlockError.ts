/**
 * ShieldBlockError
 * Application exception: thrown when a security block occurs
 */

import { SecurityEvent } from "../domain/events/SecurityEvent";

export class ShieldBlockError extends Error {
  constructor(
    message: string,
    public readonly event: SecurityEvent
  ) {
    super(message);
    this.name = "ShieldBlockError";
    Object.setPrototypeOf(this, ShieldBlockError.prototype);
  }
}
