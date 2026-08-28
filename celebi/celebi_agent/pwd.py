from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *

class PwdArguments(TaskArguments):

	def __init__(self, command_line, **kwargs):
		super().__init__(command_line, **kwargs)
		self.args = []

	async def parse_arguments(self):
		if len(self.command_line) > 0:
			raise Exception("Pwd command takes no parameters.")

class PwdCommand(CommandBase):
	cmd = "pwd"
	help_cmd = "pwd"
	argument_class = PwdArguments
	description = "Print the current working directory."
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
