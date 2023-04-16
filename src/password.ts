import crypto from "node:crypto";
import { promisify } from "node:util";

const pbkdf2 = promisify(crypto.pbkdf2);

export interface PasswordSettings {
  digest: string;
  iterations: number;
  passwordLength: number;
  saltLength: number;
}

export interface PasswordData {
  hash: string;
  salt: string;
}

export class Password {
  static settings: PasswordSettings = {
    digest: "sha512",
    saltLength: 64,
    iterations: Math.pow(10, 6),
    passwordLength: 256,
  };

  static configure(settings: Partial<PasswordSettings>) {
    this.settings = { ...this.settings, ...settings };
  }

  constructor(public hash: string, public salt: string, public settings: PasswordSettings) {}

  async verify(attempt: string) {
    const result = await Password.hash(attempt, this.salt, this.settings);
    return result.hash === this.hash;
  }

  async verifyAndUpgrade(attempt: string) {
    const result = await Password.hash(attempt, this.salt, this.settings);
    if (result.hash !== this.hash) return false;
    if (!this.needsUpgrade()) return true;
    await Password.upgrade(attempt, this);
    return true;
  }

  needsUpgrade() {
    return (
      this.settings.digest !== Password.settings.digest ||
      this.settings.passwordLength < Password.settings.passwordLength ||
      this.settings.saltLength < Password.settings.saltLength ||
      this.settings.iterations < Password.settings.iterations
    );
  }

  toString() {
    const { hash, salt, settings } = this;
    const { passwordLength, saltLength, iterations, digest } = settings;
    return `${digest}:${iterations}:${passwordLength}:${saltLength}:${hash}:${salt}`;
  }

  toJSON(): PasswordSettings & PasswordData {
    const { hash, salt, settings } = this;
    const { passwordLength, saltLength, iterations, digest } = settings;
    return { hash, salt, passwordLength, saltLength, iterations, digest };
  }

  get [Symbol.toStringTag]() {
    return "Password";
  }

  static parse(data: string | (PasswordSettings & PasswordData)) {
    if (typeof data === "object") {
      const { hash, salt, ...settings } = data;
      return new Password(hash, salt, settings);
    }
    const [digest, iterationsStr, passwordLengthStr, saltLengthStr, hash, salt] = data.split(":");
    return new Password(hash, salt, {
      digest,
      iterations: parseInt(iterationsStr, 10),
      passwordLength: parseInt(passwordLengthStr, 10),
      saltLength: parseInt(saltLengthStr, 10),
    });
  }

  static async hash(password: string, salt?: string, settings: PasswordSettings = this.settings) {
    if (!salt) salt = this.generateSalt(settings);
    const hash = await pbkdf2(password, salt, settings.iterations, settings.passwordLength, settings.digest).then((it) =>
      it.toString("base64")
    );
    return new Password(hash, salt, { ...settings });
  }

  static async upgrade(password: string, instance: Password, settings = this.settings) {
    const salt = this.generateSalt(settings);
    const hash = await pbkdf2(password, salt, settings.iterations, settings.passwordLength, settings.digest).then((it) =>
      it.toString("base64")
    );
    instance.salt = salt;
    instance.hash = hash;
    instance.settings = { ...settings };
  }

  static generateSalt(settings: PasswordSettings = this.settings) {
    return crypto.randomBytes(settings.saltLength).toString("base64");
  }
}
