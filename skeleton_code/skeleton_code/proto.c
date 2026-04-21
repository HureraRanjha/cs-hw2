#include "proto.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/crypto.h>

#define MAC_LEN    32
#define SEQ_LEN     8
#define LEN_LEN     4
#define MAX_FRAME (1u << 20)

static void put_u64_be(unsigned char out[8], uint64_t v)
{
	for (int i = 7; i >= 0; i--) { out[i] = v & 0xff; v >>= 8; }
}

static void build_iv(unsigned char iv[16], unsigned char dir, uint64_t seq)
{
	memset(iv, 0, 16);
	iv[0] = dir;
	put_u64_be(iv + 8, seq);
}

static int read_full(int fd, void* buf, size_t n)
{
	unsigned char* p = buf;
	while (n) {
		ssize_t r = recv(fd, p, n, 0);
		if (r > 0) { p += r; n -= (size_t)r; continue; }
		if (r == 0) return -1;
		if (errno == EINTR) continue;
		return -1;
	}
	return 0;
}

static int write_full(int fd, const void* buf, size_t n)
{
	const unsigned char* p = buf;
	while (n) {
		ssize_t r = send(fd, p, n, 0);
		if (r > 0) { p += r; n -= (size_t)r; continue; }
		if (r < 0 && errno == EINTR) continue;
		return -1;
	}
	return 0;
}

void cryptoInit(cryptoCtx* c, const unsigned char keys[64], int isClient)
{
	memcpy(c->aes_key, keys,      32);
	memcpy(c->mac_key, keys + 32, 32);
	c->send_dir = isClient ? 0x01 : 0x02;
	c->recv_dir = isClient ? 0x02 : 0x01;
	c->send_seq = 0;
	c->recv_seq = 0;
}

static int aes_ctr_xcrypt(const unsigned char key[32],
                          const unsigned char iv[16],
                          const unsigned char* in, unsigned char* out,
                          size_t len)
{
	EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
	if (!ctx) return -1;
	int ok = 1, outl = 0, tmpl = 0;
	if (EVP_EncryptInit_ex(ctx, EVP_aes_256_ctr(), NULL, key, iv) != 1) ok = 0;
	if (ok && EVP_EncryptUpdate(ctx, out, &outl, in, (int)len) != 1) ok = 0;
	if (ok && EVP_EncryptFinal_ex(ctx, out + outl, &tmpl) != 1) ok = 0;
	EVP_CIPHER_CTX_free(ctx);
	return ok ? 0 : -1;
}

static int compute_mac(const unsigned char mac_key[32],
                       unsigned char dir, uint64_t seq,
                       const unsigned char* ct, size_t ct_len,
                       unsigned char out[MAC_LEN])
{
	unsigned char hdr[1 + SEQ_LEN];
	hdr[0] = dir;
	put_u64_be(hdr + 1, seq);

	HMAC_CTX* h = HMAC_CTX_new();
	if (!h) return -1;
	unsigned int outlen = 0;
	int ok = 1;
	if (HMAC_Init_ex(h, mac_key, 32, EVP_sha256(), NULL) != 1) ok = 0;
	if (ok && HMAC_Update(h, hdr, sizeof hdr) != 1) ok = 0;
	if (ok && HMAC_Update(h, ct, ct_len) != 1) ok = 0;
	if (ok && HMAC_Final(h, out, &outlen) != 1) ok = 0;
	HMAC_CTX_free(h);
	return (ok && outlen == MAC_LEN) ? 0 : -1;
}

int sendEnc(int fd, cryptoCtx* c, const unsigned char* pt, size_t len)
{
	if (len > MAX_FRAME - SEQ_LEN - MAC_LEN) return -1;

	uint64_t seq = ++c->send_seq;
	unsigned char iv[16];
	build_iv(iv, c->send_dir, seq);

	unsigned char* ct = malloc(len ? len : 1);
	if (!ct) return -1;
	if (aes_ctr_xcrypt(c->aes_key, iv, pt, ct, len) != 0) {
		free(ct); return -1;
	}

	unsigned char mac[MAC_LEN];
	if (compute_mac(c->mac_key, c->send_dir, seq, ct, len, mac) != 0) {
		free(ct); return -1;
	}

	uint32_t body_len = (uint32_t)(SEQ_LEN + len + MAC_LEN);
	uint32_t net_len  = htonl(body_len);
	unsigned char seqbuf[SEQ_LEN];
	put_u64_be(seqbuf, seq);

	int rc = 0;
	if (write_full(fd, &net_len, LEN_LEN) < 0) rc = -1;
	if (!rc && write_full(fd, seqbuf, SEQ_LEN) < 0) rc = -1;
	if (!rc && len && write_full(fd, ct, len) < 0) rc = -1;
	if (!rc && write_full(fd, mac, MAC_LEN) < 0) rc = -1;

	free(ct);
	return rc;
}

ssize_t recvEnc(int fd, cryptoCtx* c, unsigned char* out, size_t maxlen)
{
	uint32_t net_len;
	if (read_full(fd, &net_len, LEN_LEN) < 0) return -1;
	uint32_t body_len = ntohl(net_len);

	if (body_len < SEQ_LEN + MAC_LEN) return -1;
	if (body_len > MAX_FRAME)         return -1;
	size_t ct_len = body_len - SEQ_LEN - MAC_LEN;
	if (ct_len > maxlen)              return -1;

	unsigned char seqbuf[SEQ_LEN];
	if (read_full(fd, seqbuf, SEQ_LEN) < 0) return -1;
	uint64_t seq = 0;
	for (int i = 0; i < SEQ_LEN; i++) seq = (seq << 8) | seqbuf[i];

	unsigned char* ct = malloc(ct_len ? ct_len : 1);
	if (!ct) return -1;
	if (ct_len && read_full(fd, ct, ct_len) < 0) { free(ct); return -1; }

	unsigned char mac_recv[MAC_LEN];
	if (read_full(fd, mac_recv, MAC_LEN) < 0) { free(ct); return -1; }

	unsigned char mac_calc[MAC_LEN];
	if (compute_mac(c->mac_key, c->recv_dir, seq, ct, ct_len, mac_calc) != 0) {
		free(ct); return -1;
	}
	if (CRYPTO_memcmp(mac_calc, mac_recv, MAC_LEN) != 0) {
		fprintf(stderr, "bad MAC, dropping\n");
		free(ct); return -1;
	}

	if (seq != c->recv_seq + 1) {
		fprintf(stderr, "bad seq (got %llu, want %llu)\n",
		        (unsigned long long)seq,
		        (unsigned long long)(c->recv_seq + 1));
		free(ct); return -1;
	}
	c->recv_seq = seq;

	unsigned char iv[16];
	build_iv(iv, c->recv_dir, seq);
	if (aes_ctr_xcrypt(c->aes_key, iv, ct, out, ct_len) != 0) {
		free(ct); return -1;
	}
	free(ct);
	return (ssize_t)ct_len;
}
