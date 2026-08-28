from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *

class PsArguments(TaskArguments):

	def __init__(self, command_line, **kwargs):
		super().__init__(command_line, **kwargs)
		self.args = []

	async def parse_arguments(self):
		if len(self.command_line) > 0:
			raise Exception("Ps command takes no parameters.")

class PsCommand(CommandBase):
	cmd = "ps"
	help_cmd = "ps"
	argument_class = PsArguments
	description = "List running processes (populates the UI process browser)."
	needs_admin = False
	version = 1
	author = "@ofasgard"
	attackmapping = ["T1057"]
	supported_ui_features = ["process_browser:list"]
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
