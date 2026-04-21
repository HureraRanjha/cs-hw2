# Secure Chat

Hurera Ranjha

## Build

```bash
cd skeleton_code/skeleton_code
make
```

Needs `gtk+-3.0`, `openssl`, `gmp` headers.

## Run

```bash
./gen-key alice Alice
./gen-key bob Bob

./chat -l -k alice -K bob.pub &
sleep 1 && ./chat -c localhost -k bob -K alice.pub &
```

Flags: `-l` listen, `-c HOST` connect, `-k` my private key, `-K` peer's public key.

## What I added

- `gen-key.c` — keypair generator
- `handshake.c/.h` — 3DH handshake (auth + PFS)
- `proto.c/.h` — AES-256-CTR + HMAC-SHA256 framed messages with seq numbers (replay protection)
- `chat.c` — hooked the above into send/recv
