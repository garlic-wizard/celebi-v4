/*
 * crypto.c — AES-256-CBC + PKCS7 + HMAC-SHA256
 *
 * Byte-compatible with Mythic's "aes256_hmac" crypto (mythic-docker/src/crypto/aes256_hmac.go):
 *   wire blob = IV(16) || AES-256-CBC-PKCS7 ciphertext || HMAC-SHA256(key, IV||ciphertext)
 *   key = 32 random bytes
 *
 * Pure C, no Windows API dependencies. Allocator is injectable (CRYPTO_MALLOC/CRYPTO_FREE)
 * and randomness is injectable (crypto_random_bytes) so this file can be unit-tested
 * on any host.
 */

#ifndef CRYPTO_MALLOC
#include <windows.h>
WINBASEAPI LPVOID WINAPI KERNEL32$VirtualAlloc(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);
WINBASEAPI BOOL WINAPI KERNEL32$VirtualFree(LPVOID lpAddress, SIZE_T dwSize, DWORD  dwFreeType);
#define CRYPTO_MALLOC(sz) KERNEL32$VirtualAlloc(0, (sz), MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE)
#define CRYPTO_FREE(p)    KERNEL32$VirtualFree((p), 0, MEM_RELEASE)
#endif

/* Provided by the agent (GetTickCount-seeded PRNG / RtlGenRandom); injectable for tests. */
void crypto_random_bytes(unsigned char *buf, size_t len);

/* ============================================================
 * SHA-256
 * ============================================================ */

typedef struct {
	unsigned int state[8];
	unsigned long long bitlen;
	unsigned char buffer[64];
	int buffer_len;
} SHA256_CTX;

static const unsigned int SHA256_K[64] = {
	0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
	0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
	0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
	0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
	0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
	0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
	0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
	0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

static unsigned int sha256_rotr(unsigned int x, int n) {
	return (x >> n) | (x << (32 - n));
}

static void sha256_transform(SHA256_CTX *ctx, const unsigned char data[64]) {
	unsigned int w[64];
	unsigned int a, b, c, d, e, f, g, h;
	int i;

	for (i = 0; i < 16; i++) {
		w[i] = ((unsigned int)data[i*4] << 24) | ((unsigned int)data[i*4+1] << 16) |
		       ((unsigned int)data[i*4+2] << 8) | (unsigned int)data[i*4+3];
	}
	for (i = 16; i < 64; i++) {
		unsigned int s0 = sha256_rotr(w[i-15], 7) ^ sha256_rotr(w[i-15], 18) ^ (w[i-15] >> 3);
		unsigned int s1 = sha256_rotr(w[i-2], 17) ^ sha256_rotr(w[i-2], 19) ^ (w[i-2] >> 10);
		w[i] = w[i-16] + s0 + w[i-7] + s1;
	}

	a = ctx->state[0]; b = ctx->state[1]; c = ctx->state[2]; d = ctx->state[3];
	e = ctx->state[4]; f = ctx->state[5]; g = ctx->state[6]; h = ctx->state[7];

	for (i = 0; i < 64; i++) {
		unsigned int S1 = sha256_rotr(e, 6) ^ sha256_rotr(e, 11) ^ sha256_rotr(e, 25);
		unsigned int ch = (e & f) ^ (~e & g);
		unsigned int temp1 = h + S1 + ch + SHA256_K[i] + w[i];
		unsigned int S0 = sha256_rotr(a, 2) ^ sha256_rotr(a, 13) ^ sha256_rotr(a, 22);
		unsigned int maj = (a & b) ^ (a & c) ^ (b & c);
		unsigned int temp2 = S0 + maj;
		h = g; g = f; f = e; e = d + temp1;
		d = c; c = b; b = a; a = temp1 + temp2;
	}

	ctx->state[0] += a; ctx->state[1] += b; ctx->state[2] += c; ctx->state[3] += d;
	ctx->state[4] += e; ctx->state[5] += f; ctx->state[6] += g; ctx->state[7] += h;
}

static void sha256_init(SHA256_CTX *ctx) {
	ctx->state[0] = 0x6a09e667; ctx->state[1] = 0xbb67ae85;
	ctx->state[2] = 0x3c6ef372; ctx->state[3] = 0xa54ff53a;
	ctx->state[4] = 0x510e527f; ctx->state[5] = 0x9b05688c;
	ctx->state[6] = 0x1f83d9ab; ctx->state[7] = 0x5be0cd19;
	ctx->bitlen = 0; ctx->buffer_len = 0;
}

static void sha256_update(SHA256_CTX *ctx, const unsigned char *data, size_t len) {
	size_t i;
	for (i = 0; i < len; i++) {
		ctx->buffer[ctx->buffer_len++] = data[i];
		if (ctx->buffer_len == 64) {
			sha256_transform(ctx, ctx->buffer);
			ctx->bitlen += 512;
			ctx->buffer_len = 0;
		}
	}
}

static void sha256_final(SHA256_CTX *ctx, unsigned char hash[32]) {
	unsigned int i;
	unsigned long long bitlen = ctx->bitlen + (unsigned long long)ctx->buffer_len * 8;

	ctx->buffer[ctx->buffer_len++] = 0x80;

	if (ctx->buffer_len > 56) {
		while (ctx->buffer_len < 64) ctx->buffer[ctx->buffer_len++] = 0;
		sha256_transform(ctx, ctx->buffer);
		ctx->buffer_len = 0;
	}
	while (ctx->buffer_len < 56) ctx->buffer[ctx->buffer_len++] = 0;

	for (i = 0; i < 8; i++) {
		ctx->buffer[56 + i] = (unsigned char)(bitlen >> (56 - i * 8));
	}
	sha256_transform(ctx, ctx->buffer);

	for (i = 0; i < 4; i++) {
		hash[i]      = (unsigned char)(ctx->state[0] >> (24 - i * 8));
		hash[i + 4]  = (unsigned char)(ctx->state[1] >> (24 - i * 8));
		hash[i + 8]  = (unsigned char)(ctx->state[2] >> (24 - i * 8));
		hash[i + 12] = (unsigned char)(ctx->state[3] >> (24 - i * 8));
		hash[i + 16] = (unsigned char)(ctx->state[4] >> (24 - i * 8));
		hash[i + 20] = (unsigned char)(ctx->state[5] >> (24 - i * 8));
		hash[i + 24] = (unsigned char)(ctx->state[6] >> (24 - i * 8));
		hash[i + 28] = (unsigned char)(ctx->state[7] >> (24 - i * 8));
	}
}

/* ============================================================
 * HMAC-SHA256
 * ============================================================ */

static void hmac_sha256(const unsigned char *key, size_t key_len,
                        const unsigned char *msg, size_t msg_len,
                        unsigned char out[32]) {
	SHA256_CTX ctx;
	unsigned char k_pad[64];
	unsigned char inner[32];
	size_t i;

	for (i = 0; i < 64; i++) {
		k_pad[i] = (i < key_len) ? key[i] : 0;
	}

	for (i = 0; i < 64; i++) k_pad[i] ^= 0x36;
	sha256_init(&ctx);
	sha256_update(&ctx, k_pad, 64);
	sha256_update(&ctx, msg, msg_len);
	sha256_final(&ctx, inner);

	for (i = 0; i < 64; i++) k_pad[i] ^= (0x36 ^ 0x5c);
	sha256_init(&ctx);
	sha256_update(&ctx, k_pad, 64);
	sha256_update(&ctx, inner, 32);
	sha256_final(&ctx, out);
}

/* ============================================================
 * AES-256
 * ============================================================ */

static const unsigned char AES_SBOX[256] = {
	0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
	0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
	0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
	0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
	0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
	0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
	0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
	0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
	0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
	0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
	0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
	0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
	0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
	0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
	0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
	0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
};

static const unsigned char AES_INV_SBOX[256] = {
	0x52,0x09,0x6a,0xd5,0x30,0x36,0xa5,0x38,0xbf,0x40,0xa3,0x9e,0x81,0xf3,0xd7,0xfb,
	0x7c,0xe3,0x39,0x82,0x9b,0x2f,0xff,0x87,0x34,0x8e,0x43,0x44,0xc4,0xde,0xe9,0xcb,
	0x54,0x7b,0x94,0x32,0xa6,0xc2,0x23,0x3d,0xee,0x4c,0x95,0x0b,0x42,0xfa,0xc3,0x4e,
	0x08,0x2e,0xa1,0x66,0x28,0xd9,0x24,0xb2,0x76,0x5b,0xa2,0x49,0x6d,0x8b,0xd1,0x25,
	0x72,0xf8,0xf6,0x64,0x86,0x68,0x98,0x16,0xd4,0xa4,0x5c,0xcc,0x5d,0x65,0xb6,0x92,
	0x6c,0x70,0x48,0x50,0xfd,0xed,0xb9,0xda,0x5e,0x15,0x46,0x57,0xa7,0x8d,0x9d,0x84,
	0x90,0xd8,0xab,0x00,0x8c,0xbc,0xd3,0x0a,0xf7,0xe4,0x58,0x05,0xb8,0xb3,0x45,0x06,
	0xd0,0x2c,0x1e,0x8f,0xca,0x3f,0x0f,0x02,0xc1,0xaf,0xbd,0x03,0x01,0x13,0x8a,0x6b,
	0x3a,0x91,0x11,0x41,0x4f,0x67,0xdc,0xea,0x97,0xf2,0xcf,0xce,0xf0,0xb4,0xe6,0x73,
	0x96,0xac,0x74,0x22,0xe7,0xad,0x35,0x85,0xe2,0xf9,0x37,0xe8,0x1c,0x75,0xdf,0x6e,
	0x47,0xf1,0x1a,0x71,0x1d,0x29,0xc5,0x89,0x6f,0xb7,0x62,0x0e,0xaa,0x18,0xbe,0x1b,
	0xfc,0x56,0x3e,0x4b,0xc6,0xd2,0x79,0x20,0x9a,0xdb,0xc0,0xfe,0x78,0xcd,0x5a,0xf4,
	0x1f,0xdd,0xa8,0x33,0x88,0x07,0xc7,0x31,0xb1,0x12,0x10,0x59,0x27,0x80,0xec,0x5f,
	0x60,0x51,0x7f,0xa9,0x19,0xb5,0x4a,0x0d,0x2d,0xe5,0x7a,0x9f,0x93,0xc9,0x9c,0xef,
	0xa0,0xe0,0x3b,0x4d,0xae,0x2a,0xf5,0xb0,0xc8,0xeb,0xbb,0x3c,0x83,0x53,0x99,0x61,
	0x17,0x2b,0x04,0x7e,0xba,0x77,0xd6,0x26,0xe1,0x69,0x14,0x63,0x55,0x21,0x0c,0x7d
};

static const unsigned char AES_RCON[11] = {0x00,0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36};

static unsigned char aes_xtime(unsigned char x) {
	return (unsigned char)((x << 1) ^ ((x >> 7) * 0x1b));
}

static void aes_expand_key(const unsigned char key[32], unsigned char rk[240]) {
	unsigned char temp[4];
	int i;

	for (i = 0; i < 32; i++) rk[i] = key[i];

	for (i = 32; i < 240; i += 4) {
		temp[0] = rk[i-4]; temp[1] = rk[i-3]; temp[2] = rk[i-2]; temp[3] = rk[i-1];

		if (i % 32 == 0) {
			unsigned char t = temp[0];
			temp[0] = AES_SBOX[temp[1]];
			temp[1] = AES_SBOX[temp[2]];
			temp[2] = AES_SBOX[temp[3]];
			temp[3] = AES_SBOX[t];
			temp[0] ^= AES_RCON[i / 32];
		} else if (i % 32 == 16) {
			temp[0] = AES_SBOX[temp[0]];
			temp[1] = AES_SBOX[temp[1]];
			temp[2] = AES_SBOX[temp[2]];
			temp[3] = AES_SBOX[temp[3]];
		}

		rk[i]   = rk[i-32] ^ temp[0];
		rk[i+1] = rk[i-31] ^ temp[1];
		rk[i+2] = rk[i-30] ^ temp[2];
		rk[i+3] = rk[i-29] ^ temp[3];
	}
}

static void aes_encrypt_block(const unsigned char in[16], unsigned char out[16], const unsigned char rk[240]) {
	unsigned char s[16], t[16];
	int round, i, r;

	for (i = 0; i < 16; i++) s[i] = in[i] ^ rk[i];

	for (round = 1; round <= 14; round++) {
		/* SubBytes */
		for (i = 0; i < 16; i++) t[i] = AES_SBOX[s[i]];
		/* ShiftRows: row r (bytes r, r+4, r+8, r+12) shifted left by r */
		for (r = 1; r < 4; r++) {
			unsigned char tmp[4];
			for (i = 0; i < 4; i++) tmp[i] = t[r + 4 * ((i + r) % 4)];
			for (i = 0; i < 4; i++) t[r + 4 * i] = tmp[i];
		}
		if (round < 14) {
			/* MixColumns */
			for (i = 0; i < 4; i++) {
				unsigned char a0 = t[4*i], a1 = t[4*i+1], a2 = t[4*i+2], a3 = t[4*i+3];
				unsigned char n0 = aes_xtime(a0), n1 = aes_xtime(a1), n2 = aes_xtime(a2), n3 = aes_xtime(a3);
				t[4*i]   = n0 ^ a1 ^ n1 ^ a2 ^ a3;
				t[4*i+1] = a0 ^ n1 ^ a2 ^ n2 ^ a3;
				t[4*i+2] = a0 ^ a1 ^ n2 ^ a3 ^ n3;
				t[4*i+3] = a0 ^ n0 ^ a1 ^ a2 ^ n3;
			}
		}
		/* AddRoundKey */
		for (i = 0; i < 16; i++) s[i] = t[i] ^ rk[round*16 + i];
	}

	for (i = 0; i < 16; i++) out[i] = s[i];
}

static void aes_decrypt_block(const unsigned char in[16], unsigned char out[16], const unsigned char rk[240]) {
	unsigned char s[16], t[16];
	int round, i, r;

	for (i = 0; i < 16; i++) s[i] = in[i] ^ rk[14*16 + i];

	for (round = 13; round >= 0; round--) {
		/* InvShiftRows: row r shifted right by r */
		for (r = 1; r < 4; r++) {
			unsigned char tmp[4];
			for (i = 0; i < 4; i++) tmp[(i + r) % 4] = s[r + 4 * i];
			for (i = 0; i < 4; i++) s[r + 4 * i] = tmp[i];
		}
		/* InvSubBytes */
		for (i = 0; i < 16; i++) s[i] = AES_INV_SBOX[s[i]];
		/* AddRoundKey */
		for (i = 0; i < 16; i++) s[i] ^= rk[round*16 + i];
		if (round > 0) {
			/* InvMixColumns */
			for (i = 0; i < 4; i++) {
				unsigned char a0 = s[4*i], a1 = s[4*i+1], a2 = s[4*i+2], a3 = s[4*i+3];
				unsigned char m2_0 = aes_xtime(a0), m2_1 = aes_xtime(a1), m2_2 = aes_xtime(a2), m2_3 = aes_xtime(a3);
				unsigned char m4_0 = aes_xtime(m2_0), m4_1 = aes_xtime(m2_1), m4_2 = aes_xtime(m2_2), m4_3 = aes_xtime(m2_3);
				unsigned char m8_0 = aes_xtime(m4_0), m8_1 = aes_xtime(m4_1), m8_2 = aes_xtime(m4_2), m8_3 = aes_xtime(m4_3);
				unsigned char x9_0  = m8_0 ^ a0, x9_1  = m8_1 ^ a1, x9_2  = m8_2 ^ a2, x9_3  = m8_3 ^ a3;
				unsigned char x11_0 = m8_0 ^ m2_0 ^ a0, x11_1 = m8_1 ^ m2_1 ^ a1, x11_2 = m8_2 ^ m2_2 ^ a2, x11_3 = m8_3 ^ m2_3 ^ a3;
				unsigned char x13_0 = m8_0 ^ m4_0 ^ a0, x13_1 = m8_1 ^ m4_1 ^ a1, x13_2 = m8_2 ^ m4_2 ^ a2, x13_3 = m8_3 ^ m4_3 ^ a3;
				unsigned char x14_0 = m8_0 ^ m4_0 ^ m2_0, x14_1 = m8_1 ^ m4_1 ^ m2_1, x14_2 = m8_2 ^ m4_2 ^ m2_2, x14_3 = m8_3 ^ m4_3 ^ m2_3;
				s[4*i]   = x14_0 ^ x11_1 ^ x13_2 ^ x9_3;
				s[4*i+1] = x9_0  ^ x14_1 ^ x11_2 ^ x13_3;
				s[4*i+2] = x13_0 ^ x9_1  ^ x14_2 ^ x11_3;
				s[4*i+3] = x11_0 ^ x13_1 ^ x9_2  ^ x14_3;
			}
		}
	}

	for (i = 0; i < 16; i++) out[i] = s[i];
}

/* ============================================================
 * CBC + PKCS7
 * ============================================================ */

static void aes_cbc_encrypt(const unsigned char key[32], const unsigned char iv[16],
                            const unsigned char *in, size_t len, unsigned char *out) {
	unsigned char rk[240];
	unsigned char prev[16];
	size_t i;

	aes_expand_key(key, rk);
	for (i = 0; i < 16; i++) prev[i] = iv[i];

	for (i = 0; i < len; i += 16) {
		unsigned char block[16];
		size_t j;
		for (j = 0; j < 16; j++) block[j] = in[i + j] ^ prev[j];
		aes_encrypt_block(block, out + i, rk);
		for (j = 0; j < 16; j++) prev[j] = out[i + j];
	}
}

static void aes_cbc_decrypt(const unsigned char key[32], const unsigned char iv[16],
                            const unsigned char *in, size_t len, unsigned char *out) {
	unsigned char rk[240];
	unsigned char prev[16];
	size_t i;

	aes_expand_key(key, rk);
	for (i = 0; i < 16; i++) prev[i] = iv[i];

	for (i = 0; i < len; i += 16) {
		unsigned char dec[16];
		size_t j;
		aes_decrypt_block(in + i, dec, rk);
		for (j = 0; j < 16; j++) out[i + j] = dec[j] ^ prev[j];
		for (j = 0; j < 16; j++) prev[j] = in[i + j];
	}
}

static size_t pkcs7_pad_len(size_t len) {
	size_t pad = 16 - (len % 16);
	return len + pad;
}

static void pkcs7_pad(const unsigned char *in, size_t len, unsigned char *out) {
	size_t pad = 16 - (len % 16);
	size_t i;
	for (i = 0; i < len; i++) out[i] = in[i];
	for (i = 0; i < pad; i++) out[len + i] = (unsigned char)pad;
}

/* returns padded length or 0 on invalid padding */
static size_t pkcs7_unpad(const unsigned char *in, size_t len, unsigned char *out) {
	size_t pad;
	size_t i;
	if (len == 0 || len % 16 != 0) return 0;
	pad = in[len - 1];
	if (pad == 0 || pad > 16 || pad > len) return 0;
	for (i = 0; i < pad; i++) {
		if (in[len - 1 - i] != pad) return 0;
	}
	for (i = 0; i < len - pad; i++) out[i] = in[i];
	return len - pad;
}

/* ============================================================
 * Public API (Mythic aes256_hmac compatible)
 * ============================================================ */

/*
 * Encrypt: out = IV(16) || AES-256-CBC-PKCS7(plaintext) || HMAC-SHA256(key, IV||CT)
 * Returns a CRYPTO_MALLOC'd buffer; *out_len set on success, 0 on failure.
 */
unsigned char *crypto_aes256_hmac_encrypt(const unsigned char key[32],
                                          const unsigned char *msg, size_t msg_len,
                                          size_t *out_len) {
	size_t padded_len = pkcs7_pad_len(msg_len);
	size_t total = 16 + padded_len + 32;
	unsigned char *padded = (unsigned char *)CRYPTO_MALLOC(padded_len);
	unsigned char *out = (unsigned char *)CRYPTO_MALLOC(total);
	unsigned char *ct = out + 16;

	if (!padded || !out) {
		if (padded) CRYPTO_FREE(padded);
		if (out) CRYPTO_FREE(out);
		*out_len = 0;
		return NULL;
	}

	pkcs7_pad(msg, msg_len, padded);
	crypto_random_bytes(out, 16); /* IV lives at the front of the output blob */
	aes_cbc_encrypt(key, out, padded, padded_len, ct);
	hmac_sha256(key, 32, out, 16 + padded_len, out + 16 + padded_len);

	CRYPTO_FREE(padded);
	*out_len = total;
	return out;
}

/*
 * Decrypt and verify: in = IV(16) || CT || HMAC(32).
 * Returns a CRYPTO_MALLOC'd buffer; *out_len set on success, 0 on failure.
 */
unsigned char *crypto_aes256_hmac_decrypt(const unsigned char key[32],
                                          const unsigned char *in, size_t in_len,
                                          size_t *out_len) {
	unsigned char expected_hmac[32];
	unsigned char *decrypted;
	unsigned char *unpadded;
	size_t ct_len;
	size_t final_len;
	int hmac_ok = 1;
	size_t i;

	*out_len = 0;

	if (in_len < 16 + 32) return NULL;
	ct_len = in_len - 16 - 32;
	if (ct_len == 0 || ct_len % 16 != 0) return NULL;

	hmac_sha256(key, 32, in, 16 + ct_len, expected_hmac);
	for (i = 0; i < 32; i++) {
		if (expected_hmac[i] != in[16 + ct_len + i]) hmac_ok = 0;
	}
	if (!hmac_ok) return NULL;

	decrypted = (unsigned char *)CRYPTO_MALLOC(ct_len);
	if (!decrypted) return NULL;
	aes_cbc_decrypt(key, in, in + 16, ct_len, decrypted);

	unpadded = (unsigned char *)CRYPTO_MALLOC(ct_len);
	if (!unpadded) {
		CRYPTO_FREE(decrypted);
		return NULL;
	}
	final_len = pkcs7_unpad(decrypted, ct_len, unpadded);
	CRYPTO_FREE(decrypted);
	if (final_len == 0) {
		CRYPTO_FREE(unpadded);
		return NULL;
	}

	*out_len = final_len;
	return unpadded;
}
