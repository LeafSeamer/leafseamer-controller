export class IdentityError extends Error {
  constructor(code) { super(code); this.name = 'IdentityError'; this.code = code; }
}
