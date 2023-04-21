import { Password } from "src/password";
import { argon2 } from "src/password/adapter/argon2";
import { bcrypt } from "src/password/adapter/bcrypt";
import { pbkdf2 } from "src/password/adapter/pbkdf2";
import { scrypt } from "src/password/adapter/scrypt";

Password.use(pbkdf2());

beforeEach(() => {
  Password.adapters.splice(0, Password.adapters.length);
});

describe("Password", () => {
  it("should throw for hashes with no matching strategy", async () => {
    expect(() => new Password("foo")).toThrow();
  });

  it("should hash a password", async () => {
    Password.use(pbkdf2());
    const password = await Password.hash("foo");
    expect(password.hash).toBeDefined();
  });

  it("should generate different hashes for the same password", async () => {
    Password.use(pbkdf2());
    const { hash: first } = await Password.hash("foo");
    const { hash: second } = await Password.hash("foo");
    expect(first).not.toEqual(second);
  });

  it("should verify passwords", async () => {
    Password.use(pbkdf2());
    const password = await Password.hash("foo");
    expect(await password.verify("foo")).toBeTruthy();
    expect(await password.verify("bar")).toBeFalsy();
  });

  it("should upgrade passwords if applicable", async () => {
    Password.use(pbkdf2());
    const password = await Password.hash("foo");
    const { hash } = password;
    expect(await password.verify("foo")).toBeTruthy();
    Password.use(argon2());
    expect(await password.verifyAndUpgrade("foo")).toBeTruthy();
    expect(password.hash).not.toEqual(hash);
  });

  it("should not downgrade passwords to lower grade adapters", async () => {
    Password.use(argon2());
    const password = await Password.hash("foo");
    Password.use(pbkdf2());
    expect(await password.verifyAndUpgrade("foo")).toBeTruthy();
    expect(password.hash.startsWith("$argon2")).toBeTruthy();
  });

  it("should serialise passwords to string", async () => {
    Password.use(pbkdf2());
    const password = await Password.hash("foo");
    const str = String(password);
    Password.use(argon2());
    const parsed = new Password(str);
    expect(password).toEqual(parsed);
    expect(await parsed.verify("foo")).toBeTruthy();
  });

  it("should be tagged as Password", async () => {
    Password.use(argon2());
    const tag = Object.prototype.toString.call(await Password.hash("foo"));
    expect(tag).toEqual("[object Password]");
  });

  describe("adapters", () => {
    it("should work with argon2", async () => {
      Password.use(argon2());
      const password = await Password.hash("foo");
      const str = String(password);
      const parsed = new Password(str);
      expect(password).toEqual(parsed);
      expect(await parsed.verify("bar")).toBeFalsy();
      expect(await parsed.verifyAndUpgrade("foo")).toBeTruthy();
    });
    it("should work with pbkdf2", async () => {
      Password.use(pbkdf2());
      const password = await Password.hash("foo");
      const str = String(password);
      const parsed = new Password(str);
      expect(password).toEqual(parsed);
      expect(await parsed.verify("bar")).toBeFalsy();
      expect(await parsed.verifyAndUpgrade("foo")).toBeTruthy();
    });
    it("should work with scrypt", async () => {
      Password.use(scrypt());
      const password = await Password.hash("foo");
      const str = String(password);
      const parsed = new Password(str);
      expect(password).toEqual(parsed);
      expect(await parsed.verify("bar")).toBeFalsy();
      expect(await parsed.verifyAndUpgrade("foo")).toBeTruthy();
    });
    it("should work with bcrypt", async () => {
      Password.use(bcrypt());
      const password = await Password.hash("foo");
      const str = String(password);
      const parsed = new Password(str);
      expect(password).toEqual(parsed);
      expect(await parsed.verify("bar")).toBeFalsy();
      expect(await parsed.verifyAndUpgrade("foo")).toBeTruthy();
    });
  });
});
