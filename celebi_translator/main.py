import mythic_container
import asyncio

import json, base64, os
from mythic_container.TranslationBase import *
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, hmac as chmac


def encrypt_aes256_hmac(key: bytes, msg: bytes) -> bytes:
	# Mythic aes256_hmac: IV(16) || AES-256-CBC-PKCS7 || HMAC-SHA256(key, IV||CT)
	iv = os.urandom(16)
	pad_len = 16 - (len(msg) % 16)
	padded = msg + bytes([pad_len]) * pad_len
	enc = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
	ct = enc.update(padded) + enc.finalize()
	h = chmac.HMAC(key, hashes.SHA256())
	h.update(iv + ct)
	return iv + ct + h.finalize()


def decrypt_aes256_hmac(key: bytes, blob: bytes) -> bytes:
	iv, ct, mac = blob[:16], blob[16:-32], blob[-32:]
	h = chmac.HMAC(key, hashes.SHA256())
	h.update(iv + ct)
	h.verify(mac)
	dec = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
	padded = dec.update(ct) + dec.finalize()
	pad = padded[-1]
	return padded[:-pad]

MESSAGE_TYPE_CHECKIN = 1
MESSAGE_TYPE_TASKING = 2
MESSAGE_TYPE_POST    = 3
MESSAGE_TYPE_UPLOAD  = 4
MESSAGE_TYPE_STAGING = 5
MESSAGE_TYPE_STAGING_REPLY = 6

POST_STATUSES = {
	1:  "success",
	2:  "error: failed to resolve PICO",
	3:  "error: missing filename",
	4:  "error: duplicate filename",
	5:  "error: upload failed",
	6:  "error: vault full",
	7:  "error: vault removal failed",
	8:  "error: missing command",
	9:  "error: unknown pico",
	10: "error: unknown command",
	11: "error: command failed"
}

POST_MESSAGES = {
}

class CelebiTranslation(TranslationContainer):
	name = "celebi_translator"
	description = "Translator used by Celebi to serialize/deserialize message data in a custom format."
	author = "@ofasgard"

	async def generate_keys(self, inputMsg: TrGenerateEncryptionKeysMessage) -> TrGenerateEncryptionKeysMessageResponse:
		# Mythic asks us for the crypto keys because mythic_encrypts=False.
		# Generate a fresh 32-byte key per payload for aes256_hmac.
		response = TrGenerateEncryptionKeysMessageResponse(Success=True)
		if inputMsg.CryptoParamValue == "aes256_hmac":
			key = os.urandom(32)
			response.EncryptionKey = key
			response.DecryptionKey = key
		else:
			response.EncryptionKey = b""
			response.DecryptionKey = b""
		return response

	def _get_crypto_key(self, crypto_keys, encrypt: bool):
		# CryptoKeys is a list of CryptoKeys(EncKey, DecKey, Value, Location).
		# Returns the raw key bytes for aes256_hmac, or None when crypto is off.
		for ck in (crypto_keys or []):
			if getattr(ck, "Value", "") == "aes256_hmac":
				return ck.EncKey if encrypt else ck.DecKey
		return None

	def _build_envelope(self, uuid: str, binary: bytes, key) -> bytes:
		# Full wire envelope: base64( uuid(36) || [encrypted] binary )
		blob = encrypt_aes256_hmac(key, binary) if key else binary
		return base64.b64encode(uuid.encode() + blob)

	async def translate_to_c2_format(self, inputMsg: TrMythicC2ToCustomMessageFormatMessage) -> TrMythicC2ToCustomMessageFormatMessageResponse:
		# The C2 is talking to the agent. We return the full wire envelope:
		# base64( uuid || [encrypted] binary ). Mythic passes our output through verbatim.
		response = TrMythicC2ToCustomMessageFormatMessageResponse(Success=True)
		key = self._get_crypto_key(inputMsg.CryptoKeys, encrypt=True)
		
		if inputMsg.Message["action"] == "checkin":
			serialized_reply = self.serialize_checkin_reply(inputMsg.Message)
		elif inputMsg.Message["action"] == "staging_rsa":
			serialized_reply = self.serialize_staging_reply(inputMsg.Message)
		elif inputMsg.Message["action"] == "get_tasking":
			serialized_reply = self.serialize_tasking_reply(inputMsg.Message)
		elif inputMsg.Message["action"] == "post_response":
			# Is this a normal reply to post_response, or are we replying to an upload request?
			if "responses" in inputMsg.Message and "chunk_data" in inputMsg.Message["responses"][0]:
				serialized_reply = self.serialize_upload_reply(inputMsg.Message)
			else:
				serialized_reply = self.serialize_post_reply(inputMsg.Message)
		else:
			serialized_reply = b""
		
		response.Message = self._build_envelope(inputMsg.UUID, serialized_reply, key)
		return response

	async def translate_from_c2_format(self, inputMsg: TrCustomMessageToMythicC2FormatMessage) -> TrCustomMessageToMythicC2FormatMessageResponse:
		# The agent is talking to the C2. Mythic already stripped the outer UUID,
		# so inputMsg.Message is the (possibly encrypted) binary payload.
		response = TrCustomMessageToMythicC2FormatMessageResponse(Success=True)
		
		msg = inputMsg.Message
		key = self._get_crypto_key(inputMsg.CryptoKeys, encrypt=False)
		if key:
			try:
				msg = decrypt_aes256_hmac(key, msg)
			except Exception as e:
				response.Success = False
				response.Error = "failed to decrypt agent message: {}".format(e)
				return response
		
		if msg[0] == MESSAGE_TYPE_CHECKIN:
			response.Message = self.deserialize_checkin_request(msg)
			return response
		if msg[0] == MESSAGE_TYPE_STAGING:
			response.Message = self.deserialize_staging_request(msg)
			return response
		if msg[0] == MESSAGE_TYPE_TASKING:
			response.Message = self.deserialize_tasking_request(msg)
			return response
		if msg[0] == MESSAGE_TYPE_POST:
			response.Message = self.deserialize_post_request(msg)
			response.Message = self.resolve_post_messages(response.Message)
			return response
		if msg[0] == MESSAGE_TYPE_UPLOAD:
			response.Message = self.deserialize_upload_request(msg)
			return response
		
		raise Exception("UNRECOGNISED INPUT MESSAGE TYPE: {}".format(msg))

	def deserialize_checkin_request(self, packed_msg):
		data = {}
		data["action"] = "checkin"
		
		offset = 1
		
		# Parse the payload UUID (Mythic links the callback to the payload by it;
		# the envelope UUID may be a staging tempUUID during RSA EKE).
		data["uuid"] = ""
		for byte in packed_msg[offset:]:
			if byte == 0x00:
				break
			data["uuid"] += chr(byte)
			offset += 1
		
		offset +=1 # terminator byte
		
		# Parse PID
		pid_raw = packed_msg[offset:offset+4]
		data["pid"] = int.from_bytes(pid_raw, "little", signed=False)
		offset += 4
		
		# Parse username
		data["user"] = ""
		for byte in packed_msg[offset:]:
			if byte == 0x00:
				break
			data["user"] += chr(byte)
			offset += 1
		
		offset +=1 # terminator byte
		
		# Parse hostname
		data["host"] = ""
		for byte in packed_msg[offset:]:
			if byte == 0x00:
				break
			data["host"] += chr(byte)
			offset += 1
		
		offset +=1 # terminator byte
		
		# Parse domain
		data["domain"] = ""
		for byte in packed_msg[offset:]:
			if byte == 0x00:
				break
			data["domain"] += chr(byte)
			offset += 1
		
		offset +=1 # terminator byte
		
		# Parse the host's local IP (optional, newer agents; absent = no ip).
		data["ip"] = ""
		if offset < len(packed_msg):
			for byte in packed_msg[offset:]:
				if byte == 0x00:
					break
				data["ip"] += chr(byte)
				offset += 1
		
		# Hardcoded parameters
		data["architecture"] = "x64"
		data["os"] = "Windows"
		
		return data
		
	def deserialize_staging_request(self, packed_msg):
		data = {}
		data["action"] = "staging_rsa"
		
		offset = 1
		
		# Parse session id
		data["session_id"] = ""
		for byte in packed_msg[offset:]:
			if byte == 0x00:
				break
			data["session_id"] += chr(byte)
			offset += 1
		
		offset +=1 # terminator byte
		
		# Parse public key (base64 PKCS#1 DER)
		data["pub_key"] = ""
		for byte in packed_msg[offset:]:
			if byte == 0x00:
				break
			data["pub_key"] += chr(byte)
			offset += 1
		
		return data
		
	def deserialize_tasking_request(self, packed_msg):
		data = {}
		data["action"] = "get_tasking"
		data["tasking_size"] = packed_msg[1]
		# Celebi's p2p child pairs one request with one reply; stop Mythic from
		# batching auto-routed delegate tasks into this (egress) agent's response.
		data["get_delegate_tasks"] = False
		offset = 2

		# Delegate messages from linked p2p children (parent side).
		if offset + 4 <= len(packed_msg):
			delegate_count = int.from_bytes(packed_msg[offset:offset+4], "little", signed=False)
			offset += 4
			delegates = []
			for _ in range(delegate_count):
				entry = {}
				entry["uuid"] = self._read_cstr(packed_msg, offset); offset = self._after_cstr(packed_msg, offset)
				entry["c2_profile"] = self._read_cstr(packed_msg, offset); offset = self._after_cstr(packed_msg, offset)
				entry["message"] = self._read_cstr(packed_msg, offset); offset = self._after_cstr(packed_msg, offset)
				delegates.append(entry)
			if delegates:
				data["delegates"] = delegates

			# Callback graph edge updates (link/unlink).
			if offset + 4 <= len(packed_msg):
				edge_count = int.from_bytes(packed_msg[offset:offset+4], "little", signed=False)
				offset += 4
				edges = []
				for _ in range(edge_count):
					entry = {}
					entry["source"] = self._read_cstr(packed_msg, offset); offset = self._after_cstr(packed_msg, offset)
					entry["destination"] = self._read_cstr(packed_msg, offset); offset = self._after_cstr(packed_msg, offset)
					entry["action"] = self._read_cstr(packed_msg, offset); offset = self._after_cstr(packed_msg, offset)
					entry["c2_profile"] = self._read_cstr(packed_msg, offset); offset = self._after_cstr(packed_msg, offset)
					edges.append(entry)
				if edges:
					data["edges"] = edges

		return data

	def _read_cstr(self, buf, offset):
		end = buf.index(0, offset)
		return buf[offset:end].decode("latin-1")

	def _after_cstr(self, buf, offset):
		return buf.index(0, offset) + 1
		
	def deserialize_post_request(self, packed_msg):
		data = {}
		data["action"] = "post_response"
		
		response = {}
		offset = 1
		
		# Parse task ID
		response["task_id"] = ""
		for byte in packed_msg[offset:]:
			if byte == 0x00:
				break
			response["task_id"] += chr(byte)
			offset += 1
		
		offset +=1 # terminator byte   
		
		# Parse task output
		response["user_output"] = ""
		for byte in packed_msg[offset:]:
			if byte == 0x00:
				break
			response["user_output"] += chr(byte)
			offset += 1
		
		offset +=1 # terminator byte   
		
		# Parse task status
		response["status"] = ""
		for byte in packed_msg[offset:]:
			if byte == 0x00:
				break
			response["status"] += chr(byte)
			offset += 1
		
		offset +=1 # terminator byte		   
		
		# Parse the completed flag (1 = task finished, 0 = more responses coming).
		# Default to completed if the byte is missing (legacy messages).
		response["completed"] = bool(packed_msg[offset]) if offset < len(packed_msg) else True
		offset += 1

		# Optional structured payloads: flags byte + NUL-terminated blobs
		# (bit 0 = file browser, bit 1 = process browser).
		if offset < len(packed_msg):
			flags = packed_msg[offset]
			offset += 1
			if flags & 1:
				blob = self._read_cstr(packed_msg, offset); offset = self._after_cstr(packed_msg, offset)
				response["file_browser"] = self.parse_fb_blob(blob)
			if flags & 2:
				blob = self._read_cstr(packed_msg, offset); offset = self._after_cstr(packed_msg, offset)
				response["process_browser"] = self.parse_ps_blob(blob)

		data["responses"] = [response]
		return data

	def parse_fb_blob(self, blob):
		# Blob format (tab/newline delimited):
		#   line 0: parent_path \t name \t is_file \t size \t modify_ms \t access_ms \t success
		#   lines 1+: child_name \t is_file \t size \t modify_ms \t access_ms
		def fields(line):
			return line.split("\t")
		def to_int(v, default=0):
			try:
				return int(v)
			except (ValueError, TypeError):
				return default
		lines = blob.split("\n") if blob else []
		meta = fields(lines[0]) if lines else []
		fb = {
			"host": "",
			"is_file": meta[2] == "1" if len(meta) > 2 else False,
			"permissions": {},
			"name": meta[1] if len(meta) > 1 else "",
			"parent_path": meta[0] if len(meta) > 0 else "",
			"success": (meta[6] != "0") if len(meta) > 6 else True,
			"access_time": to_int(meta[5]) if len(meta) > 5 else 0,
			"modify_time": to_int(meta[4]) if len(meta) > 4 else 0,
			"size": to_int(meta[3]) if len(meta) > 3 else 0,
			"files": [],
		}
		for line in lines[1:]:
			if not line:
				continue
			f = fields(line)
			fb["files"].append({
				"is_file": f[1] == "1" if len(f) > 1 else False,
				"permissions": {},
				"name": f[0] if len(f) > 0 else "",
				"access_time": to_int(f[4]) if len(f) > 4 else 0,
				"modify_time": to_int(f[3]) if len(f) > 3 else 0,
				"size": to_int(f[2]) if len(f) > 2 else 0,
			})
		return fb

	def parse_ps_blob(self, blob):
		# Blob format: one process per line:
		#   pid \t ppid \t name \t user \t arch \t bin_path \t session \t integrity \t command_line \t start_time
		def to_int(v, default=0):
			try:
				return int(v)
			except (ValueError, TypeError):
				return default
		procs = []
		if blob:
			for line in blob.split("\n"):
				if not line:
					continue
				f = line.split("\t")
				procs.append({
					"process_id": to_int(f[0]) if len(f) > 0 else 0,
					"parent_process_id": to_int(f[1]) if len(f) > 1 else 0,
					"name": f[2] if len(f) > 2 else "",
					"user": f[3] if len(f) > 3 else "",
					"architecture": f[4] if len(f) > 4 else "",
					"bin_path": f[5] if len(f) > 5 else "",
					"session_id": to_int(f[6]) if len(f) > 6 else 0,
					"integrity_level": to_int(f[7]) if len(f) > 7 else 0,
					"command_line": f[8] if len(f) > 8 else "",
					"start_time": f[9] if len(f) > 9 else "",
				})
		return {"host": "", "os": "", "processes": procs}
		
	def deserialize_upload_request(self, packed_msg):
		data = {}
		data["action"] = "post_response"
		
		response = {}
		offset = 1
		
		# Parse task ID
		response["task_id"] = ""
		for byte in packed_msg[offset:]:
			if byte == 0x00:
				break
			response["task_id"] += chr(byte)
			offset += 1
		
		offset +=1 # terminator byte  
			
		response["upload"] = {}
		
		# Parse file ID
		response["upload"]["file_id"] = ""
		for byte in packed_msg[offset:]:
			if byte == 0x00:
				break
			response["upload"]["file_id"] += chr(byte)
			offset += 1
			
		offset +=1 # terminator byte
		
		# Parse chunk size
		chunk_size_raw = packed_msg[offset:offset+4]
		response["upload"]["chunk_size"] = int.from_bytes(chunk_size_raw, "little", signed=False)
		offset += 4
		
		# Parse chunk number
		chunk_num_raw = packed_msg[offset:offset+4]
		response["upload"]["chunk_num"] = int.from_bytes(chunk_num_raw, "little", signed=False)
		offset += 4		
		
		data["responses"] = [response]
		return data

	def serialize_staging_reply(self, msg):
		# [6][temp_uuid\0][session_key\0][session_id\0]
		output = bytearray()
		output.append(MESSAGE_TYPE_STAGING_REPLY)
		output.extend(msg["uuid"].encode())
		output.append(0)
		output.extend(msg["session_key"].encode())
		output.append(0)
		output.extend(msg["session_id"].encode())
		output.append(0)
		return bytes(output)
		
	def serialize_checkin_reply(self, msg):
		output = bytearray()
		
		output.append(MESSAGE_TYPE_CHECKIN)
		
		output.extend(msg["id"].encode())
		output.append(0)
		
		output.extend(msg["status"].encode())
		output.append(0)
		
		return bytes(output)
		
	def serialize_tasking_reply(self, msg):
		output = bytearray()
		
		output.append(MESSAGE_TYPE_TASKING)
		
		task_count = len(msg["tasks"])
		output.extend(task_count.to_bytes(1, "big"))
		
		for task in msg["tasks"]:
				output.extend(task["id"].encode())
				output.append(0)
				
				output.extend(task["command"].encode())
				output.append(0)
				
				raw_params = self.process_parameters(task["command"], task["parameters"])
				output.extend(raw_params.encode())
				output.append(0)
				
				rounded_timestamp = int(task["timestamp"])
				output.extend(rounded_timestamp.to_bytes(4, "little"))
		
		# Delegate responses for linked p2p children (parent side).
		# The messages are already-encrypted full agentMessages; pass them verbatim.
		delegates = msg.get("delegates", [])
		output.extend(len(delegates).to_bytes(4, "little"))
		for delegate in delegates:
			output.extend(delegate["uuid"].encode())
			output.append(0)
			output.extend(delegate["message"].encode())
			output.append(0)
			output.extend(delegate.get("new_uuid", delegate.get("mythic_uuid", "")).encode())
			output.append(0)
		
		return bytes(output)
	
	def serialize_post_reply(self, msg):
		output = bytearray()
		
		output.append(MESSAGE_TYPE_POST)
		
		# This is currently ignored by the agent, so don't bother actually sending the data for now...
		
		return bytes(output)
		
	def serialize_upload_reply(self, msg):
		output = bytearray()
		
		output.append(MESSAGE_TYPE_UPLOAD)
		
		if len(msg["responses"]) > 1:
			raise Exception("Celebi doesn't currently support more than one response in a post_response reply (found {})".format(len(msg["responses"])))
		
		response = msg["responses"][0]
		
		if response["status"] == "error":
			raise Exception("Failed to respond to upload request with error: {}".format(response["error"]))
			
		output.extend(response["total_chunks"].to_bytes(4, "little"))
		output.extend(response["chunk_num"].to_bytes(4, "little"))
		
		output.extend(response["chunk_data"].encode())
		output.append(0)
		
		return bytes(output)

	def resolve_post_messages(self, msg):
		# Converts a "terse" numerical status field from the agent into a human-readable status message.
		try:
			status_str = msg["responses"][0]["status"]
			status = int(status_str)
			
			if status in POST_STATUSES:
				msg["responses"][0]["status"] = POST_STATUSES[status]	

		except ValueError:
			pass

		return msg

	def process_parameters(self, cmd, params):
		# Helper function to convert JSON file parameters into the raw strings expected by the agent.
		try:
			param_data = json.loads(params)
		except:
			return params
		
		if cmd == "sleep":
			return str(param_data["interval"])
		
		if cmd == "register":
			return param_data["name"] + "\t" + param_data["file"]
			
		if cmd == "unregister":
			return param_data["name"]
			
		if cmd == "execute_pico":
			args = param_data["pico_args"] if "pico_args" in param_data else ""
			return param_data["name"] + "\t" + args
			
		if cmd == "morph":
			return param_data["command"] + "\t" + param_data["pico_name"]
			
		if cmd == "link":
			profile = param_data["c2_profile"]
			host = param_data["host"]
			pipename = param_data.get("pipename", "")
			port = str(param_data.get("port", "0"))
			return profile + "\t" + host + "\t" + pipename + "\t" + port
			
		if cmd == "unlink":
			profile = param_data.get("c2_profile", "")
			host = param_data.get("host", "")
			return profile + "\t" + host + "\t\t0"
			
		if cmd == "spawn":
			return str(param_data.get("file", "")) + "\t" + str(param_data.get("port", 0))
			
		if cmd == "spawnto":
			return param_data.get("path", "")

		if cmd == "ls":
			return param_data.get("path", "")

		if cmd == "ps":
			return ""

		if cmd == "cat":
			return param_data.get("path", "")

		if cmd == "pwd":
			return ""

		if cmd == "change":
			return str(param_data.get("sleep", 0)) + "\t" + str(param_data.get("jitter", 0))

		raise Exception("Unrecognised command parameter! Original JSON: {}".format(params))

mythic_container.mythic_service.start_and_run_forever()
