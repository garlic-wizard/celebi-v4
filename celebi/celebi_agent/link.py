from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *

import json

class LinkArguments(TaskArguments):

	def __init__(self, command_line, **kwargs):
		super().__init__(command_line, **kwargs)
		self.args = [
			CommandParameter(
				name="c2_profile",
				cli_name="c2_profile",
				display_name="C2 Profile",
				type=ParameterType.ChooseOne,
				choices=["smb", "tcp"],
				parameter_group_info=[ ParameterGroupInfo(required=True, ui_position=0) ]
			),
			CommandParameter(
				name="host",
				cli_name="host",
				display_name="Host",
				type=ParameterType.String,
				parameter_group_info=[ ParameterGroupInfo(required=True, ui_position=1) ]
			),
			CommandParameter(
				name="pipename",
				cli_name="pipename",
				display_name="Pipe Name",
				type=ParameterType.String,
				parameter_group_info=[ ParameterGroupInfo(required=False, ui_position=2) ]
			),
			CommandParameter(
				name="port",
				cli_name="port",
				display_name="Port",
				type=ParameterType.Number,
				parameter_group_info=[ ParameterGroupInfo(required=False, ui_position=3) ]
			)
		]

	async def parse_arguments(self):
		if len(self.command_line) == 0:
			raise Exception("Please provide a JSON blob with c2_profile, host and the profile's parameters.")
		if self.command_line[0] != "{":
			raise Exception("Require JSON blob, but got raw command line.")

		self.load_args_from_json_string(self.command_line)

		if len(self.get_arg("c2_profile")) == 0:
			raise Exception("You must provide a value for the c2_profile argument")
		if len(self.get_arg("host")) == 0:
			raise Exception("You must provide a value for the host argument")
		if self.get_arg("c2_profile") == "smb" and len(self.get_arg("pipename") or "") == 0:
			raise Exception("You must provide a pipename for the smb profile")
		if self.get_arg("c2_profile") == "tcp" and self.get_arg("port") is None:
			raise Exception("You must provide a port for the tcp profile")

class LinkCommand(CommandBase):
	cmd = "link" # Name of the command
	help_cmd = "link" # Help information presented to the user
	argument_class = LinkArguments # The class used for processing & validating arguments
	description = "Connect to a p2p child (smb/tcp profile) and start relaying its traffic."
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
