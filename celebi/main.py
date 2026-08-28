import mythic_container
import asyncio

import celebi_agent.celebi
import celebi_agent.sleep
import celebi_agent.exit
import celebi_agent.whoami
import celebi_agent.register
import celebi_agent.unregister
import celebi_agent.execute_pico
import celebi_agent.morph
import celebi_agent.link
import celebi_agent.unlink
import celebi_agent.spawn
import celebi_agent.spawnto
import celebi_agent.ls
import celebi_agent.ps
import celebi_agent.cat
import celebi_agent.pwd
import celebi_agent.change

mythic_container.mythic_service.start_and_run_forever()
