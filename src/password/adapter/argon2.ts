import { hash, verify as argonVerify, Options } from "@node-rs/argon2";
import { PasswordHashAdapter } from "src/password/types";

export function argon2(options?: Omit<Options, "salt" | "raw">): PasswordHashAdapter {
  async function hashNeedsUpgrade() {
    return false;
  }

  async function hashAndSalt(password: string): Promise<string> {
    return await hash(password, options);
  }

  async function verify(password: string, hash: string): Promise<boolean> {
    return await argonVerify(hash, password);
  }

  function hashMatchesStrategy(hash: string): boolean {
    return hash.startsWith("$argon2");
  }

  return {
    priority: 30,
    hashNeedsUpgrade,
    hashAndSalt,
    verify,
    hashMatchesStrategy,
  };
}
