import { PasswordHashAdapter } from "src/password";
import { hash, compare as verify } from "bcrypt";

export interface BcryptOptions {
  saltRounds?: number;
}

export function bcrypt(options: BcryptOptions = {}): PasswordHashAdapter {
  const { saltRounds = 10 } = options;
  return {
    priority: 10,
    verify,
    async hashAndSalt(password: string): Promise<string> {
      return await hash(password, saltRounds);
    },
    hashMatchesStrategy(hash: string): boolean {
      return hash.startsWith("$2a$") || hash.startsWith("$2b$");
    },
    async hashNeedsUpgrade(): Promise<boolean> {
      return false;
    },
  };
}
