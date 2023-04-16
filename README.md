[![Maintainability](https://api.codeclimate.com/v1/badges/70945023a0a33ac65fbb/maintainability)](https://codeclimate.com/github/propero-oss/security/maintainability)
[![Test Coverage](https://api.codeclimate.com/v1/badges/70945023a0a33ac65fbb/test_coverage)](https://codeclimate.com/github/propero-oss/security/test_coverage)


# @propero/security


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
```typescript
import { Password } from "@propero/security"

// create new hash and salt
const password = await Password.hash("foo");

// serialise to string or json
const json = JSON.stringify(password);
const text = password.toString();

// parse password strings or json
const parsedJson = Password.parse(JSON.parse(json));
const parsetText = Password.parse(text);

// verify passwords
await password.verify("foo") // true
await password.verify("bar") // false
await parsedJson.verify("foo") // true
await parsedText.verify("foo") // true

// modify default settings
Password.configure({ digest: "sha512", iterations: 20000 });

// upgrade passwords in place
const before = password.hash;
await password.verifyAndUpgrade("foo"); // true
password.hash === before // false

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
      to: String,
      from: Password.parse.bind(Password),
    }
  })
  password!: Password;
  
}
```
