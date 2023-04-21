import crypto, { ScryptOptions } from "node:crypto";
import { promisify } from "node:util";
import { PasswordHashAdapter } from "src/password";

const scryptAsync = promisify(crypto.scrypt) as any;

export interface ScryptAdapterOptions extends ScryptOptions {
  keyLength?: number;
  saltLength?: number;
}

export function scrypt(options: ScryptAdapterOptions = {}): PasswordHashAdapter {
  const { keyLength = 256, saltLength = 128, ...scryptOptions } = options;

  function serialiseOptions(keyLength: number, saltLength: number, options: ScryptOptions) {
    const { N, p, r, cost, maxmem, blockSize, parallelization } = options;
    return Object.entries({ N, p, r, cost, maxmem, blockSize, parallelization, keyLength, saltLength })
      .map(([key, value]) => `${key}=${value ?? ""}`)
      .join(";");
  }

  function deserialiseOptions(str: string) {
    return Object.fromEntries(
      str
        .split(";")
        .map((part) => part.split("="))
        .map(([key, value]) => (value === "undefined" || value === "" ? [key, undefined] : [key, parseInt(value, 10)]))
    ) as Partial<ScryptAdapterOptions>;
  }

  function serialiseHash(hash: string, salt: string, keyLength: number, saltLength: number, options: ScryptOptions) {
    return `$scrypt$${serialiseOptions(keyLength, saltLength, options)}$${hash}$${salt}`;
  }

  function deserialiseHash(hashed: string) {
    const [, , options, hash, salt] = hashed.split("$");
    return { options: deserialiseOptions(options), hash, salt };
  }

  function generateSalt(saltLength: number) {
    return crypto.randomBytes(saltLength).toString("base64");
  }

  async function hashAndSalt(password: string): Promise<string> {
    const salt = generateSalt(saltLength);
    const hash = await scryptAsync(password, salt, keyLength, scryptOptions);
    return serialiseHash(hash.toString("base64"), salt, keyLength, saltLength, scryptOptions);
  }

  async function verify(password: string, hashed: string): Promise<boolean> {
    const { options, hash, salt } = deserialiseHash(hashed);
    const match = await scryptAsync(password, salt, options.keyLength, options);
    return hash === match.toString("base64");
  }

  function hashMatchesStrategy(hash: string): boolean {
    return hash.startsWith("$scrypt$");
  }

  function comparePreferDefined<T extends Record<string, number | undefined>>(a: T, b: T, keys: (keyof T)[]) {
    for (const key of keys) {
      if (a[key] != null && b[key] != null)
        if (a[key]! < b[key]!) return true;
        else continue;
      if (a[key] != null || b[key] != null) return true;
    }
    return false;
  }

  async function hashNeedsUpgrade(hash: string): Promise<boolean> {
    const { options } = deserialiseHash(hash);
    return comparePreferDefined(options, { ...scryptOptions, keyLength, saltLength }, [
      "N",
      "cost",
      "r",
      "p",
      "maxmem",
      "blockSize",
      "keyLength",
      "saltLength",
    ]);
  }

  return {
    priority: 20,
    hashMatchesStrategy,
    verify,
    hashAndSalt,
    hashNeedsUpgrade,
  };
}
