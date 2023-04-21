import crypto from "node:crypto";
import { promisify } from "node:util";
import { PasswordHashAdapter } from "src/password/types";

const pbkdf2Async = promisify(crypto.pbkdf2);

export interface Pbkdf2Settings {
  digest: string;
  iterations: number;
  passwordLength: number;
  saltLength: number;
  hashesPerSecond?: number;
}

function roundTo(n: number, places: number) {
  const factor = Math.pow(10, places);
  return Math.round(n / factor) * factor;
}

export function pbkdf2(settings: Partial<Pbkdf2Settings> = {}): PasswordHashAdapter {
  const prefix = "$pbkdf2$",
    testIterations = 1000;
  const {
    digest = "sha512",
    saltLength = 128,
    passwordLength = 256,
    iterations: definedIterations = 10000,
    hashesPerSecond = 10,
  } = settings;
  let iterations = testIterations;

  async function initialise() {
    const before = Date.now();
    await hashAndSalt("test-speed");
    const time = Date.now() - before;
    const iterationsPerSecond = roundTo((1000 * testIterations) / time, 3);
    iterations = Math.max(1000, definedIterations, iterationsPerSecond / hashesPerSecond);
  }

  function parseHash(hash: string) {
    const [, digestStr, iterationsStr, passwordLengthStr, saltLengthStr, hashStr, saltStr] = hash.split(":");
    return {
      digest: digestStr,
      iterations: parseInt(iterationsStr, 10),
      passwordLength: parseInt(passwordLengthStr, 10),
      saltLength: parseInt(saltLengthStr, 10),
      hash: hashStr,
      salt: saltStr,
    };
  }

  async function generateSalt() {
    return crypto.randomBytes(saltLength).toString("base64");
  }

  async function hashAndSalt(password: string) {
    const salt = await generateSalt();
    const hash = await pbkdf2Async(password, salt, iterations, passwordLength, digest);
    return `${prefix}:${digest}:${iterations}:${passwordLength}:${saltLength}:${hash.toString("base64")}:${salt}`;
  }

  function hashMatchesStrategy(hash: string) {
    return hash.startsWith(prefix);
  }

  async function hashNeedsUpgrade(hash: string): Promise<boolean> {
    const parsed = parseHash(hash);
    return !(
      parsed.digest === digest &&
      parsed.iterations >= iterations &&
      parsed.passwordLength >= passwordLength &&
      parsed.saltLength >= saltLength
    );
  }

  async function verify(password: string, hash: string) {
    const parsed = parseHash(hash);
    const counterpart = await pbkdf2Async(password, parsed.salt, parsed.iterations, parsed.passwordLength, parsed.digest);
    return counterpart.toString("base64") === parsed.hash;
  }

  return {
    priority: 0,
    initialise,
    hashMatchesStrategy,
    hashAndSalt,
    hashNeedsUpgrade,
    verify,
  };
}
