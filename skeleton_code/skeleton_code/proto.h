#pragma once
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

/* Frame: [len u32 BE][seq u64 BE][ciphertext][hmac-sha256 32B]
 * AES-256-CTR; MAC over (dir || seq || ciphertext). */

typedef struct {
	unsigned char aes_key[32];
	unsigned char mac_key[32];
	unsigned char send_dir;
	unsigned char recv_dir;
	uint64_t send_seq;
	uint64_t recv_seq;
} cryptoCtx;

void cryptoInit(cryptoCtx* c, const unsigned char keys[64], int isClient);
int  sendEnc(int fd, cryptoCtx* c, const unsigned char* pt, size_t len);
ssize_t recvEnc(int fd, cryptoCtx* c, unsigned char* out, size_t maxlen);
