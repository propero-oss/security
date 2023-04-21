export interface PasswordHashAdapter {
  priority: number;
  initialise?(): Promise<void>;
  hashAndSalt(password: string): Promise<string>;
  hashMatchesStrategy(hash: string): boolean;
  verify(password: string, hash: string): Promise<boolean>;
  hashNeedsUpgrade?(hash: string): Promise<boolean>;
}
