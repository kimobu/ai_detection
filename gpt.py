from openai import AsyncOpenAI
from dotenv import load_dotenv
import logging
import asyncio
import os
import json

MAX_RETRIES = 5
INITIAL_BACKOFF = 1
MAX_BACKOFF = 30
MAX_CONCURRENT_REQUESTS = 100

SYSTEM_PROMPT = """
INSTRUCTIONS
You are an expert security professional at Dunder Mifflin paper company. Your security knowledge and judgment are unparalleled. You analyze security data, and output analysis in JSON format. You always follow user instructions.
You will be given a list of processes and commands from a host that have been surfaced to analyze. Your job is to analyze the activity for malicious activity. You will provide a 1-10 score of the suspiciousness of the process group and tag the command with the corresponding MITRE ATT&CK tactic, if applicable.

TAGGING
Here are the MITRE tactics you are to classify suspicious commands by:
"initial_access"
"execution"
"persistence"
"privilege_escalation"
"defense_evasion"
"credential_access"
"discovery"
"lateral_movement"
"collection"
"exfiltration"
"command_and_control"

OUTPUT
{"hostname": "hostname"
"group_leader_pid": "group_leader.pid",
"analysis": "<your own analysis of 400 or fewer words>",
"mitre_tag": "[<mitre tag>]",
"verdict": <benign_or_suspicious>,
"suspicious_score": <your score of 0-10>,
}
- Very important. Always follow this ioutput format. Do not ever deviate from it. Expand array to include multiple command analyses.

ANALYSIS
- You are provided with activity from related processes. During your analysis take into account the sequence of activity in the commands and frame each command in the context of the previous commands. For example, a kubectl exec execution might be benign if the endpoint proceeds to just read a log file, but if the command is followed with a curl command to a server to run a script, this is more suspicious. Several commands might appear benign in isolation, but in aggregate could indicate malicious behavior. Analyze commands with this in mind.
- Only analyze commands that are presented in the array of commands passed in the input. Do not generate your own examples of commands. Do not return the example commands or variations on the example commands.
- Only mark verdict as "suspicious" if you are certain the activity is highly suspicious and merits review by an analyst. Keep false positives to a minimum. We have a small team and taking up time responding to false positive alerts will decrease our overall security by giving us less time to respond to and triage true positives.
- You will be provided with the role and department of the employee whose commands are being analyzed. Take the individuals role into account when analyzing the command chain. Where relevant, explain why a command may be fitting or anomalous for the user, given their role. Use this information to inform your scoring of the process group and your verdict. Highly anomalous commands for a given role should be scored as more suspicious. No users should be engaging in activity that involved setting up reverse shells, reading a high number of credentials, or exfiltrating large amounts of data.

"""

class GPT:
    def __init__(self, log_level: int = logging.INFO):
        self.logger = logging.getLogger("GPT")
        self.logger.setLevel(log_level)
        if not self.logger.hasHandlers():
            formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
            handler = logging.StreamHandler()
            handler.setFormatter(formatter)
            self.logger.addHandler(handler)
        load_dotenv()
        openai_api_key = os.getenv("OPENAI_API_KEY")
        self.client = AsyncOpenAI(api_key=openai_api_key)
        self.semaphore = asyncio.Semaphore(MAX_CONCURRENT_REQUESTS)
        self.logger.info("GPT initialized")

    async def analyze(self, user_message: str, model: str = "gpt-4o", temp: float = 0.1 ):
        system_message = SYSTEM_PROMPT
        response_format={
            "type": "json_schema",
            "json_schema": {
                "name": "security_analysis_schema",
                "schema": {
                    "type": "object",
                    "properties": {
                        "process.group_leader.pid": {
                            "description": "The process group PID",
                            "type": "string"
                        },
                        "host.name": {
                            "description": "The device hostname",
                            "type": "string"
                        },
                        "analysis": {
                            "description": "Your analysis of 400 or fewer words",
                            "type": "string",
                            "maxLength": 2400  
                        },
                        "suspicious_score": {
                            "description": "A score from 0 to 10 for suspiciousness",
                            "type": "number",
                            "minimum": 0,
                            "maximum": 10
                        },
                        "verdict": {
                            "description": "benign or suspicious",
                            "type": "string",
                            "enum": ["benign", "suspicious"]
                        },
                        "mitre_tag": {
                            "description": "An array of MITRE tags, e.g. '[]'",
                            "type": "string"
                        }
                    },
                    "required": ["process.group_leader.pid", "analysis", "suspicious_score", "verdict", "mitre_tag"],
                    "additionalProperties": False
                }
            }
        }
        self.logger.debug("Analyzing grouped commands")
        return await self._fetch_with_retries(user_message, system_message, response_format, model, temp)

    async def _fetch_with_retries(self, user_message: str, system_message: str, response_format: dict, model: str, temp: float, max_retries: int = MAX_RETRIES):
        retries = 0
        backoff = INITIAL_BACKOFF
        self.logger.debug(f"user_message: {user_message}")
        self.logger.debug(f"system_message: {system_message}")
        self.logger.debug(f"response_format: {response_format}")
        async with self.semaphore:
            while retries <= max_retries:
                try:
                    response = await self.client.chat.completions.create(
                        model = model,
                        response_format = response_format,
                        temperature = temp,
                        messages = [
                            {"role": "system", "content": system_message},
                            {"role": "user", "content": user_message}
                        ]
                    )
                    self.logger.debug(f"GPT response: {response}")
                    return json.loads(response.choices[0].message.content)
                except Exception as e:
                    if hasattr(e, "http_status") and e.http_status == 503:
                        self.logger.warning(f"ServiceUnavailableError encountered. Retrying in {backoff} seconds")
                        await asyncio.sleep(backoff)
                        retries += 1
                        backoff = min(backoff * 2, MAX_BACKOFF)
                    else:
                        self.logger.error(f"An error occurred: {e}")
                        raise e
            raise Exception(f"Failed to fetch after {max_retries} retries")
        