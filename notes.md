# 2of3

Generate keys to `2of3.0.json`...`2of3.2.json`

```
RUST_LOG=info cargo run --example keygen 2 3 2of3 --use-range-proofs
```

Sign "Some message" and get output as "r", "s" signature parts

```
RUST_LOG=info cargo run --example sign 2 3 2of3 "Some message"
```

Verify signature

```
RUST_LOG=info cargo run --example verify "Some message" \
    <sig_r> \
    <sig_s> \
    <pubkey_x> \
    <pubkey_y>
```

"hash": "675006c89393d754f558c4b969ffb106380218650ac4e3099c406007ddf092f0"
"r": "222821d281f1b005048243ae3ac470a35776e5def0b2423b20533f431239ca6a",
"s": "51d3f5842893b1afb26279a407f7618f1f0c7c32c69f112d1b903e5b58bcc1a3",

# 3of5

Generate keys to `3of5.0.json`...`3of5.4.json`

```
RUST_LOG=info cargo run --example keygen 3 5 3of5 --use-range-proofs
```

Sign "Some message" and get output as "r", "s" signature parts

```
RUST_LOG=info cargo run --example sign 3 5 3of5 "Some message"
```

Verify signature

```
RUST_LOG=info cargo run --example verify "Some message" \
    <sig_r> \
    <sig_s> \
    <pubkey_x> \
    <pubkey_y>
```

"hash": "675006c89393d754f558c4b969ffb106380218650ac4e3099c406007ddf092f0"
"r": "10589cf5f8953eecd1163f6c4d14e99d8bd79b157befada4f075355008b5f3a",
"s": "ba0100c4021450dc07fb8c900ee2f6c4d792cc5a6bb842465c798da211a69b6d",
