from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *

import json

class LsArguments(TaskArguments):

	def __init__(self, command_line, **kwargs):
		super().__init__(command_line, **kwargs)
		self.args = [
			CommandParameter(
				name="path",
				cli_name="path",
				display_name="Path",
				type=ParameterType.String,
				parameter_group_info=[ ParameterGroupInfo(required=False, ui_position=0) ]
			)
		]

	async def parse_arguments(self):
		if len(self.command_line) == 0:
			self.add_arg("path", "")
			return
		if self.command_line[0] != "{":
			raise Exception("Require JSON blob, but got raw command line.")
		self.load_args_from_json_string(self.command_line)
		# The UI file browser tasks with {host, path, file, full_path}; map that
		# onto our single path argument.
		params = json.loads(self.command_line)
		if "full_path" in params and params["full_path"]:
			self.add_arg("path", params["full_path"])
		elif "path" in params and params["path"]:
			if "file" in params and params["file"]:
				self.add_arg("path", params["path"] + "\\" + params["file"])
			else:
				self.add_arg("path", params["path"])

class LsCommand(CommandBase):
	cmd = "ls"
	help_cmd = "ls [path]"
	argument_class = LsArguments
	description = "List the contents of a directory (populates the UI file browser)."
	needs_admin = False
	version = 1
	author = "@ofasgard"
	attackmapping = ["T1083"]
	supported_ui_features = ["file_browser:list"]
	attributes = CommandAttributes(
		builtin=True,
		suggested_command=True,
	)

	async def create_go_tasking(self, taskData: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
		response = PTTaskCreateTaskingMessageResponse(
			TaskID=taskData.Task.ID,
			Success=True,
		)
		return response
