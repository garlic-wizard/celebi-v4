from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *

class CdArguments(TaskArguments):

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
			raise Exception("Please provide a path to change into.")
		if self.command_line[0] == "{":
			self.load_args_from_json_string(self.command_line)
		else:
			self.add_arg("path", self.command_line)

class CdCommand(CommandBase):
	cmd = "cd"
	help_cmd = "cd <path>"
	argument_class = CdArguments
	description = "Change the working directory of the agent."
	needs_admin = False
	version = 1
	author = "@ofasgard"
	attackmapping = []
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
		return response
