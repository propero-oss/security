[![Maintainability](https://api.codeclimate.com/v1/badges/70945023a0a33ac65fbb/maintainability)](https://codeclimate.com/github/propero-oss/security/maintainability)
[![Test Coverage](https://api.codeclimate.com/v1/badges/70945023a0a33ac65fbb/test_coverage)](https://codeclimate.com/github/propero-oss/security/test_coverage)


# @propero/security
safe and simple handling of passwords, tokens, etc

## Installation
```shell
pnpm add @propero/security
```
```shell
npm i @propero/secutiry
```
```shell
yarn add @propero/security
```

## Passwords
Please use argon2 if possible, as at the time of writing this (21/04/2023), it is the most secure supported adapter.

### Supported Adapters
- argon2
- scrypt
- bcrypt
- pbkdf2


### Usage
```typescript
import { Password } from "@propero/security"
import { argon2 } from "@propero/security/password/adapter/argon2";
import { scrypt } from "@propero/security/password/adapter/scrypt";
import { bcrypt2 } from "@propero/security/password/adapter/bcrypt";
import { pbkdf2 } from "@propero/security/password/adapter/pbkdf2";

// register various adapters
Password
  .use(scrypt())
  .use(pbkdf2());

// create new hash and salt
// this will use the highest priority adapter, in this case scrypt
const password = await Password.hash("foo");

// serialise to string
const text = password.toString();

// parse password strings
const parset = new Password(text);

// verify passwords
await password.verify("foo") // true
await password.verify("bar") // false
await parsed.verify("foo") // true

// add adapters at any point
Password
  .use(bcrypt2())
  .use(argon2());

// upgrade passwords in place
const before = password.hash;
await password.verifyAndUpgrade("foo"); // true
password.hash === before // false, now uses argon2

// usage with typeorm
@Entity("user")
export class User {
  @PrimaryGeneratedColumn("uuid")
  uuid!: string;

  @Column("varchar")
  username!: string;

  // ... user fields

  @Column("varchar", {
    transformer: {
      to: (password) => password.toString(),
      from: (hash) => new Password(hash),
    }
  })
  password!: Password;

}
```

### Writing your own adapters
Any object matching the `PasswordHashAdapter` is a valid adapter.

```typescript
import { Password, PasswordHashAdapter } from "@propero/security";

function plainText(): PasswordHashAdapter {
  return {
    priority: -1, // higher numbers are preferred, 0 is pbkdf2, 40 is argon2
    initialise: async () => {
      // this is run once before the first hash is created or verified
      // it can be omitted
      console.log("don't ever use plain text!!!");
    },
    hashAndSalt: async (password: string) => "$plain$" + password,
    hashMatchesStrategy: (hash: string) => hash.startsWith("$plain$"),
    verify: async (password: string, hash: string) => hash.slice(7) === password,
    hashNeedsUpgrade: async (hash: string) => false,
  }
}

Password.use(plainText());

```
