import json
from openai import OpenAI
import os
import time
from datetime import datetime
from pydantic import BaseModel
import tiktoken
import re

input_file_name = "../test_data/LLM/aminer_no_attack_lines.json"
dataset = "aminer"

token_limit = 2000000
request_limit = 10000
max_output_tok = 1000

def getAdditionalAlerts(number_of_lines, alert_positions, line_number):
    line_number = line_number - 1 # substract 1 so index-based access is possible again

    text = " ".join(alert_positions)
    positions = [int(num) for num in (re.findall(r'\d+', text))]

    alert_pos = positions[line_number]
    first_alert_pos = 0 if alert_pos-number_of_lines <= 0 else alert_pos-number_of_lines

    additional_alerts = []

    with open("../test_data/fox_" + dataset + ".json") as all_alerts:
        for i, line in enumerate(all_alerts):
            if i in range(first_alert_pos, alert_pos):
                additional_alerts.append(line)

    return additional_alerts


def calculateMaxRequestsPerMinute(rpm_limit, tpm_limit, message, max_output_tokens):
    encoding = tiktoken.encoding_for_model("gpt-4o")
    number_input_tokens = len(encoding.encode(message))

    tokens_per_request = number_input_tokens + max_output_tokens + 300 # 300 is buffer
    rpm_by_token_limit = tpm_limit // tokens_per_request

    return min(rpm_limit, rpm_by_token_limit)


# System message
system_message = """You are a security analyst.  You will be given an IDS (Intrusion Detection System) log entry in JSON format called `ids_line`.  Your task is to classify the alert and return the output in the following JSON schema:

{
    "anomaly_timestamp": "<value from Timestamps in ids_line>",
    "classification": "TP | FP",
    "mitre_technique": ["<techniques from MITRE ATT&CK>"],
    "description": "<short reasoning about the classification>"
}

Follow these rules:
- Extract the anomaly timestamp from 'Timestamps'.
- Always output valid JSON only.
- Classification:
- TP = true positive (legitimate malicious activity)
- FP = false positive (benign or misclassified activity)
- For mitre_technique, use the best fitting MITRE ATT&CK techniques, you can also supply more than one but stick to the minimum.
- Use short but precise description

Additionally, to help with classification here are some additional alerts that happened right before the alert that you should classify:
"""

with open("../llm_keys/openai.txt", "r") as file:
    os.environ["OPENAI_API_KEY"] = file.read().strip()

class Classification(BaseModel):
    anomaly_timestamp: str
    classification: str
    mitre_technique: list[str]
    description: str


with open(input_file_name, "r") as input_lines:
    file_name = input_file_name.split("/")[-1].split(".")[0] + "_lines.txt"
    with open("../test_data/LLM/" + file_name) as alert_pos:
        alert_positions = alert_pos.readlines()

    for i in range(0,20):
        print(f"\nStarting run {i+1}")
        number_of_lines = i + 1
        additional_alerts = []
        processed_lines = []

        timestamp = datetime.now().strftime('%d_%m_%Y_%H_%M')
        filename = "./" + input_file_name[:-5].replace("../test_data/LLM/", "../preprocessing_files/add_alerts/simple/" + str(number_of_lines) + "_run/chatgpt/") + "_" + timestamp + "_results.json"

        input_lines.seek(0)
        for j, line in enumerate(input_lines, start=1):

            working_message = system_message
            string_line = line

            result_entry = {
                "line_number": j,
                "input": line
            }

            line = json.loads(line)

            additional_alerts = getAdditionalAlerts(number_of_lines, alert_positions, j)

            if not additional_alerts:
                result_entry["alert_collection_error"] = "There are no available other alerts before the alert."
                result_entry["output"] = "No request was sent as no additional log lines were available within in the time frame."
                processed_lines.append(result_entry)
                continue

            working_message += ' '.join([str(line) for line in additional_alerts])
            client = OpenAI()

            response = client.responses.parse(
                model="gpt-4o-2024-08-06",
                temperature=0.0,
                top_p=1.0,
                max_output_tokens= max_output_tok,
                text_format=Classification,
                input=[
                    {"role": "system", "content": working_message},
                    {"role": "user", "content": f" Now classify the following IDS line:\n\nids_line:\n{json.dumps(line)}"}
                ]
            )

            result_entry["output"] = response.output_parsed.model_dump()

            processed_lines.append(result_entry)

            with open(filename, "w") as f:
                json.dump(processed_lines, f, indent=2)
            print("Line number " + str(j) + " processed.")
            message = working_message + f"Now classify the following IDS line:\n\nids_line:\n{json.dumps(line)}"
            request_estimate_per_second = calculateMaxRequestsPerMinute(request_limit, token_limit, message, max_output_tok) // 60
            if request_estimate_per_second < 60:
                time.sleep(2)
            else:
                time.sleep(1 / request_estimate_per_second)

        print(f"{len(processed_lines)} lines processed from {input_file_name}")

        with open(filename, "w") as f:
            json.dump(processed_lines, f, indent=2)

        print("Results saved to" + filename)
