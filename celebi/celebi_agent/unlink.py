from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *

import json

class UnlinkArguments(TaskArguments):

	def __init__(self, command_line, **kwargs):
		super().__init__(command_line, **kwargs)
		self.args = [
			CommandParameter(
				name="c2_profile",
				cli_name="c2_profile",
				display_name="C2 Profile",
				type=ParameterType.ChooseOne,
				choices=["smb", "tcp"],
				parameter_group_info=[ ParameterGroupInfo(required=False, ui_position=0) ]
			),
			CommandParameter(
				name="host",
				cli_name="host",
				display_name="Host",
				type=ParameterType.String,
				parameter_group_info=[ ParameterGroupInfo(required=False, ui_position=1) ]
			)
		]

	async def parse_arguments(self):
		# Profile+host are optional: without them the agent unlinks its most
		# recent peer; with them it matches a specific link.
		if len(self.command_line) > 0 and self.command_line[0] == "{":
			self.load_args_from_json_string(self.command_line)

class UnlinkCommand(CommandBase):
	cmd = "unlink" # Name of the command
	help_cmd = "unlink" # Help information presented to the user
	argument_class = UnlinkArguments # The class used for processing & validating arguments
	description = "Disconnect from a linked p2p child (optionally matching c2_profile/host) and remove its edge from the callback graph."
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
