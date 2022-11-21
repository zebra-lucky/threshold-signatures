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