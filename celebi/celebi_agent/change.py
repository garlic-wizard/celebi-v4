from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *

import json

class ChangeArguments(TaskArguments):

	def __init__(self, command_line, **kwargs):
		super().__init__(command_line, **kwargs)
		self.args = [
			CommandParameter(
				name="sleep",
				cli_name="sleep",
				display_name="Sleep (seconds)",
				type=ParameterType.Number,
				parameter_group_info=[ ParameterGroupInfo(required=True, ui_position=0) ]
			),
			CommandParameter(
				name="jitter",
				cli_name="jitter",
				display_name="Jitter (%)",
				type=ParameterType.Number,
				parameter_group_info=[ ParameterGroupInfo(required=True, ui_position=1) ]
			)
		]

	async def parse_arguments(self):
		if len(self.command_line) == 0:
			raise Exception("Please provide the new sleep interval (seconds) and jitter (percent).")
		if self.command_line[0] != "{":
			raise Exception("Require JSON blob, but got raw command line.")
		self.load_args_from_json_string(self.command_line)
		if self.get_arg("sleep") is None:
			raise Exception("You must provide a value for the sleep argument")
		if self.get_arg("jitter") is None:
			raise Exception("You must provide a value for the jitter argument")

class ChangeCommand(CommandBase):
	cmd = "change"
	help_cmd = "change [sleep] [jitter]"
	argument_class = ChangeArguments
	description = "Change the agent's sleep interval (seconds) and jitter (percent)."
	needs_admin = False
	version = 1
	author = "@ofasgard"
	attackmapping = []
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
