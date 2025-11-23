import os
import time
import json
from datetime import datetime, timedelta
from pydantic import BaseModel
from google.genai import Client, types
import re

input_file_name = "../test_data/LLM/wazuh_attack_lines.json"
dataset = "wazuh"
year_dataset = 2022
max_number_of_lines = 15

def getAdditionalAlerts(max_seconds, alert_positions, line_number, alert_timestamp):
    line_number = line_number - 1 # substract 1 so index-based access is possible again

    text = " ".join(alert_positions)
    positions = [int(num) for num in (re.findall(r'\d+', text))]

    alert_pos = positions[line_number]
    first_alert_pos = 0 if alert_pos-max_number_of_lines <= 0 else alert_pos-max_number_of_lines

    possible_alerts = []

    with open("../test_data/fox_" + dataset + ".json") as all_alerts:
        for i, line in enumerate(all_alerts):
            if i in range(first_alert_pos, alert_pos):
                possible_alerts.append(line)

    if dataset == "wazuh":
        alert_time = datetime.strptime(alert_timestamp, f"%Y-%m-%dT%H:%M:%S.%fZ")
    elif dataset == "aminer":
        alert_time = datetime.fromtimestamp(float(alert_timestamp))
    earliest_time = alert_time - timedelta(seconds=max_seconds)
    additional_alerts = [line for line in possible_alerts if alert_time >= parseTime(line) >= earliest_time]

    return additional_alerts

def parseTime(alert_line):
    alert = json.loads(alert_line)

    if '@timestamp' in alert.keys():
        date = datetime.strptime(alert['@timestamp'], f"%Y-%m-%dT%H:%M:%S.%fZ")
    elif 'LogData' in alert.keys():
        date = datetime.fromtimestamp(float(alert['LogData']['Timestamps'][0]))
    return date

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

with open("../llm_keys/gemini.txt", "r") as file:
    os.environ["GEMINI_API_KEY"] = file.read().strip()

class Classification(BaseModel):
    anomaly_timestamp: str
    classification: str
    mitre_technique: list[str]
    description: str

with open(input_file_name, "r") as input_lines:
    file_name = input_file_name.split("/")[-1].split(".")[0] + "_lines.txt"
    with open("../test_data/LLM/" + file_name) as alert_pos:
        alert_positions = alert_pos.readlines()

    request_stats = []

    for i in range(0,10):
        print(f"\nStarting run {(i+1) * 5}")
        number_of_seconds = (i + 1) * 5
        additional_alerts = []
        processed_lines = []

        timestamp = datetime.now().strftime('%d_%m_%Y_%H_%M')
        filename = "./" + input_file_name[:-5].replace("../test_data/LLM/", "../preprocessing_files/add_alerts/time/" + str(number_of_seconds) + "_run/gemini/") + "_" + timestamp + "_results.json"

        input_lines.seek(0)
        runstats = []

        for j, line in enumerate(input_lines, start=1):
            working_message = system_message
            string_line = line

            result_entry = {
                "line_number": j,
                "input": line
            }

            line = json.loads(line)

            if dataset == "aminer":
                alert_timestamp = line['LogData']['Timestamps'][0]
            elif dataset == "wazuh":
                alert_timestamp = line['@timestamp']
            else:
                print("Selected dataset does not exist!")
                exit()

            additional_alerts = getAdditionalAlerts(number_of_seconds, alert_positions, j, alert_timestamp)

            runstats.append(
                {
                    "line_nr": j,
                    "nr_add_lines": len(additional_alerts)
                }
            )

            if not additional_alerts:
                result_entry["alert_collection_error"] = "There are no available other alerts before the alert."
                result_entry["output"] = "No request was sent as no additional log lines were available within in the time frame."
                processed_lines.append(result_entry)
                continue

            working_message += ' '.join([str(line) for line in additional_alerts])
            client = Client()

            invalid_output = True
            repeat_counter = 0

            while invalid_output:
                response = client.models.generate_content(
                    model="gemini-2.5-flash-lite", # gemine-2.5-flash and gemini-2.5-pro throw a lot of 503 errors due to being overloaded
                    contents=[
                        {"role": "user", "parts": [{"text": f"Now classify the following IDS line:\n\nids_line:\n{json.dumps(line)}"}]}
                    ],
                    config=types.GenerateContentConfig(
                        temperature=0.0,
                        max_output_tokens=1000,
                        top_p=1.0,
                        system_instruction=working_message,
                        response_mime_type="application/json",
                        response_schema=Classification,
                    )
                )

                try:
                    result = Classification.model_validate_json(response.text).model_dump()
                    invalid_output = False
                except Exception as e:
                    print(response.text)
                    if(repeat_counter == 5):
                        result = "Processing was not possible."
                        break
                    print(f"Error parsing response for line {j}: {e}. Trying again.")
                    time.sleep(20)
                    repeat_counter += 1

            result_entry["output"] = result

            processed_lines.append(result_entry)

            with open(filename, "w") as f:
                json.dump(processed_lines, f, indent=2)

            print("Line number " + str(j) + " processed.")
            time.sleep(2) # 5 seconds per minute break to avoid rate limits

        request_stats.append(
            {
                "run_nr": i,
                "line_results": runstats
            }
        )

        print(f"{len(processed_lines)} lines processed from {input_file_name}")

        with open(filename, "w") as f:
            json.dump(processed_lines, f, indent=2)

        print("Results saved to" + filename)

    request_stats_file = "./" + input_file_name[:-5].replace("../test_data/LLM/", "../preprocessing_files/add_alerts/time/") + "_" + timestamp + "_gemini_request_stats.json"
    with open(request_stats_file, "w") as f:
        json.dump(request_stats, f, indent=2)
