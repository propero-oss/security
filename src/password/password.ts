import { PasswordHashAdapter } from "src/password/types";

export class Password {
  constructor(public hash: string, public adapter?: PasswordHashAdapter) {
    this.adapter ??= this.determineStrategy(hash);
  }

  determineStrategy(hash: string) {
    for (const adapter of Password.adapters) if (adapter.hashMatchesStrategy(hash)) return adapter;
    throw new RangeError(`No matching strategy for hash: ${hash}`);
  }

  async verify(attempt: string) {
    return this.adapter?.verify(attempt, this.hash);
  }

  async verifyAndUpgrade(attempt: string) {
    if (!(await this.verify(attempt))) return false;
    if (!(await this.needsUpgrade())) return true;
    this.adapter = Password.preferredAdapter;
    this.hash = await this.adapter.hashAndSalt(attempt);
    return true;
  }

  async needsUpgrade() {
    if (await this.adapter?.hashNeedsUpgrade?.(this.hash)) return true;
    return this.adapter !== Password.preferredAdapter;
  }

  get [Symbol.toStringTag]() {
    return "Password";
  }

  toString() {
    return this.hash;
  }

  static adapters: PasswordHashAdapter[] = [];
  static initialised: Map<PasswordHashAdapter, boolean> = new Map();

  static use(adapter: PasswordHashAdapter) {
    Password.adapters.push(adapter);
    Password.adapters.sort(({ priority: a }, { priority: b }) => b - a);
    return this;
  }

  static get preferredAdapter() {
    return Password.adapters[0];
  }

  static async hash(password: string) {
    const adapter = this.preferredAdapter;
    if (!Password.initialised.get(adapter) && adapter.initialise) {
      await adapter.initialise();
      Password.initialised.set(adapter, true);
    }
    const hash = await adapter.hashAndSalt(password);
    return new Password(hash, adapter);
  }
}
