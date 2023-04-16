import { Password } from "src/password";

Password.configure({ iterations: 1000 }); // faster tests

describe("Password", () => {
  it("should hash a password", async () => {
    const password = await Password.hash("foo");
    expect(password.hash).toBeDefined();
  });

  it("should generate different salts for the same password", async () => {
    const { salt: first } = await Password.hash("foo");
    const { salt: second } = await Password.hash("foo");
    expect(first).not.toEqual(second);
  });

  it("should verify passwords", async () => {
    const password = await Password.hash("foo");
    expect(await password.verify("foo")).toBeTruthy();
    expect(await password.verify("bar")).toBeFalsy();
  });

  it("should upgrade passwords if applicable", async () => {
    const password = await Password.hash("foo");
    const { hash, salt, settings } = password;
    Password.configure({ iterations: 2000 });
    expect(await password.verifyAndUpgrade("foo")).toBeTruthy();
    expect(password.hash).not.toEqual(hash);
    expect(password.salt).not.toEqual(salt);
    expect(password.settings.iterations).not.toEqual(settings.iterations);
    Password.configure({ iterations: 1000 });
  });

  it("should not downgrade passwords", async () => {
    const password = await Password.hash("foo");
    const { hash, salt, settings } = password;
    Password.configure({ iterations: 500 });
    expect(await password.verifyAndUpgrade("foo")).toBeTruthy();
    expect(password.hash).toEqual(hash);
    expect(password.salt).toEqual(salt);
    expect(password.settings.iterations).toEqual(settings.iterations);
    Password.configure({ iterations: 1000 });
  });

  it("should serialise passwords to json", async () => {
    const password = await Password.hash("foo", "bar");
    const json = JSON.stringify(password);
    expect(JSON.parse(json)).toEqual({
      hash: "drpt7Fw/amBwTXMKKkuqHFlvJ4rjVAjuXWfs4JQsFPQkUrqGvYh/Dmv4Y0TPl8wKVjb6wQ7EvNYvZHE/YGjSJbnZ1eptHuqtg/d1RDx6bEt801ergxp85bws0k57LJMHH9K5yx9XTxt7rsYvSQfcQHcdvJnnMOcMrX8a+o2VdP2fWQTSwSx8ZrE4ozxc7WuYpeCevVD97BYhiLfpmsLMLb5atcgHLlpxLPNUeyHFMAqfNJi4oOVbQ6wdWLO5JrIXEgI+WBuIR6G7/NwGJ3qyAm5c8gBNMObO3mfhgdrsarB4qtFSoVmwrNBHVPxitwGiR2JlInpwhWSzmkqaI0zBeA==",
      salt: "bar",
      iterations: 1000,
      digest: "sha512",
      saltLength: 64,
      passwordLength: 256,
    });
  });

  it("should serialise passwords to string", async () => {
    const password = await Password.hash("foo", "bar");
    const str = String(password);
    expect(str).toEqual(
      [
        "sha512",
        1000,
        256,
        64,
        "drpt7Fw/amBwTXMKKkuqHFlvJ4rjVAjuXWfs4JQsFPQkUrqGvYh/Dmv4Y0TPl8wKVjb6wQ7EvNYvZHE/YGjSJbnZ1eptHuqtg/d1RDx6bEt801ergxp85bws0k57LJMHH9K5yx9XTxt7rsYvSQfcQHcdvJnnMOcMrX8a+o2VdP2fWQTSwSx8ZrE4ozxc7WuYpeCevVD97BYhiLfpmsLMLb5atcgHLlpxLPNUeyHFMAqfNJi4oOVbQ6wdWLO5JrIXEgI+WBuIR6G7/NwGJ3qyAm5c8gBNMObO3mfhgdrsarB4qtFSoVmwrNBHVPxitwGiR2JlInpwhWSzmkqaI0zBeA==",
        "bar",
      ].join(":")
    );
  });

  it("should deserialise passwords from json", async () => {
    const password = Password.parse({
      hash: "drpt7Fw/amBwTXMKKkuqHFlvJ4rjVAjuXWfs4JQsFPQkUrqGvYh/Dmv4Y0TPl8wKVjb6wQ7EvNYvZHE/YGjSJbnZ1eptHuqtg/d1RDx6bEt801ergxp85bws0k57LJMHH9K5yx9XTxt7rsYvSQfcQHcdvJnnMOcMrX8a+o2VdP2fWQTSwSx8ZrE4ozxc7WuYpeCevVD97BYhiLfpmsLMLb5atcgHLlpxLPNUeyHFMAqfNJi4oOVbQ6wdWLO5JrIXEgI+WBuIR6G7/NwGJ3qyAm5c8gBNMObO3mfhgdrsarB4qtFSoVmwrNBHVPxitwGiR2JlInpwhWSzmkqaI0zBeA==",
      salt: "bar",
      iterations: 1000,
      digest: "sha512",
      saltLength: 64,
      passwordLength: 256,
    });
    expect(await password.verify("foo")).toBeTruthy();
  });

  it("should deserialise passwords from strings", async () => {
    const password = Password.parse(
      [
        "sha512",
        1000,
        256,
        64,
        "drpt7Fw/amBwTXMKKkuqHFlvJ4rjVAjuXWfs4JQsFPQkUrqGvYh/Dmv4Y0TPl8wKVjb6wQ7EvNYvZHE/YGjSJbnZ1eptHuqtg/d1RDx6bEt801ergxp85bws0k57LJMHH9K5yx9XTxt7rsYvSQfcQHcdvJnnMOcMrX8a+o2VdP2fWQTSwSx8ZrE4ozxc7WuYpeCevVD97BYhiLfpmsLMLb5atcgHLlpxLPNUeyHFMAqfNJi4oOVbQ6wdWLO5JrIXEgI+WBuIR6G7/NwGJ3qyAm5c8gBNMObO3mfhgdrsarB4qtFSoVmwrNBHVPxitwGiR2JlInpwhWSzmkqaI0zBeA==",
        "bar",
      ].join(":")
    );
    expect(await password.verify("foo")).toBeTruthy();
  });

  it("should be tagged as Password", async () => {
    const tag = Object.prototype.toString.call(await Password.hash("foo"));
    expect(tag).toEqual("[object Password]");
  });
});
