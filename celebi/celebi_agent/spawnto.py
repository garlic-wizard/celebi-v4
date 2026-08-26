from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *

import json

class SpawntoArguments(TaskArguments):

	def __init__(self, command_line, **kwargs):
		super().__init__(command_line, **kwargs)
		self.args = [
			CommandParameter(
				name="path",
				cli_name="path",
				display_name="Path",
				type=ParameterType.String,
				parameter_group_info=[ ParameterGroupInfo(required=True, ui_position=0) ]
			)
		]

	async def parse_arguments(self):
		if len(self.command_line) == 0:
			raise Exception("Please provide the path to the sacrificial process (e.g. C:\\Windows\\System32\\notepad.exe).")
		if self.command_line[0] != "{":
			raise Exception("Require JSON blob, but got raw command line.")
		self.load_args_from_json_string(self.command_line)
		if len(self.get_arg("path")) == 0:
			raise Exception("You must provide a value for the path argument")

class SpawntoCommand(CommandBase):
	cmd = "spawnto"
	help_cmd = "spawnto"
	argument_class = SpawntoArguments
	description = "Set the sacrificial process path used by the spawn command to inject new agents into."
	needs_admin = False
	version = 1
	author = "@ofasgard"
	attackmapping = ["T1055"]
	supported_ui_features = []
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
