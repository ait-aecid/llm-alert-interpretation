import os
import time
import json
from datetime import datetime
from pydantic import BaseModel
from google.genai import Client, types
from os import listdir
from os.path import isfile, join
from datetime import datetime, timedelta
import re

input_file_name = "../test_data/LLM/wazuh_no_attack_lines.json"
dataset = "wazuh"
year_dataset = 2022
max_number_of_lines = 15

def getAdditionalLogDataAminer(max_seconds, filename, ip, raw_data, mapping):
    folder_name = mapping[ip]

    log_file_path = "../test_data/Log_data/" + folder_name + "/logs/"
    shortened_filepath = filename.replace("/var/log/", "")
    splitted = shortened_filepath.split("/")
    cleaned_file_name = splitted[-1]
    log_file_path += shortened_filepath.replace(cleaned_file_name, "")

    # special case for possible faulty file path
    if "error-error" in cleaned_file_name:
        cleaned_file_name = cleaned_file_name.replace("error-error", "error")
    elif "access-access" in cleaned_file_name:
        cleaned_file_name = cleaned_file_name.replace("access-access", "access")
    elif "intranet-access.log" in cleaned_file_name or "intranet-error.log" in cleaned_file_name:
        cleaned_file_name = cleaned_file_name.replace("intranet-", "intranet.price.fox.org-")
    elif "mail-access.log" in cleaned_file_name:
        cleaned_file_name = cleaned_file_name.replace("mail-", "mail.price.fox.org-")
    elif "cloud-access.log" in cleaned_file_name:
        cleaned_file_name = cleaned_file_name.replace("cloud-", "cloud.price.fox.org-")


    onlyfiles = [f for f in listdir(log_file_path.replace(cleaned_file_name, "")) if isfile(join(log_file_path.replace(cleaned_file_name, ""), f))]
    filtered_file_names = [file for file in onlyfiles if cleaned_file_name in file]

    line_found = False
    result = []

    for file in filtered_file_names:
        if line_found:
            break

        year = 1970
        timestamp_str = "Jan 01 00:00:00"
        alert_time = datetime.strptime(f"{year} {timestamp_str}", "%Y %b %d %H:%M:%S")

        try:
            with open(log_file_path + file, "r") as log_file:
                log_lines = log_file.readlines()
                log_lines = [x.strip() for x in log_lines]
                pos = len(log_lines) + 100 # out of range

                for i, line in enumerate(log_lines):
                    if line.strip() == raw_data[0]:
                        pos = i
                        line_found = True
                        alert_time = parse_time(line, year_dataset)
                        break

                if alert_time is None:
                    continue

                possible_lines = log_lines[pos-max_number_of_lines: pos]
                earliest_time = alert_time - timedelta(seconds=max_seconds)
                result = [line for line in possible_lines if alert_time >= parse_time(line, year_dataset) >= earliest_time]
        except FileNotFoundError:
            return "Error: Log file not found"
    return result

def getAdditionalLogDataWazuh(max_seconds, filename, host_identifier, raw_data, mapping):
    if "." in host_identifier:
        host_identifier = mapping[host_identifier]

    log_file_path = "../test_data/Log_data/" + host_identifier + "/logs/"
    shortened_filepath = filename.replace("/var/log/", "")
    splitted = shortened_filepath.split("/")
    cleaned_file_name = splitted[-1]
    log_file_path += shortened_filepath.replace(cleaned_file_name, "")

    # special case for possible faulty file path
    if "error-error" in cleaned_file_name:
        cleaned_file_name = cleaned_file_name.replace("error-error", "error")
    elif "access-access" in cleaned_file_name:
        cleaned_file_name = cleaned_file_name.replace("access-access", "access")
    elif "intranet-access.log" in cleaned_file_name or "intranet-error.log" in cleaned_file_name:
        cleaned_file_name = cleaned_file_name.replace("intranet-", "intranet.price.fox.org-")

    onlyfiles = [f for f in listdir(log_file_path.replace(cleaned_file_name, "")) if isfile(join(log_file_path.replace(cleaned_file_name, ""), f))]
    filtered_file_names = [file for file in onlyfiles if cleaned_file_name in file]

    line_found = False
    result = []
    alert_time = None

    for file in filtered_file_names:
        if line_found:
            break

        try:
            with open(log_file_path + file, "r") as log_file:
                log_lines = log_file.readlines()
                log_lines = [x.strip() for x in log_lines]
                pos = len(log_lines) + 100 # out of range

                for i, line in enumerate(log_lines):
                    if raw_data.startswith("2022-01-"):
                        line = json.loads(line)
                        if line["timestamp"] == raw_data:
                            pos = i
                            line_found = True
                            line = str(line)

                            alert_time = parse_time(line, year_dataset)
                            break
                    elif line.strip() == raw_data:
                        pos = i
                        line_found = True
                        alert_time = parse_time(line, year_dataset)
                        break
                    elif "type=AVC msg=audit(" in line.strip() or "type=SYSCALL msg=audit(" in line.strip() or "type=PROCTITLE msg=audit(" in line.strip():
                        if line.strip() in raw_data:
                            pos = min(i, pos)
                            line_found = True
                            alert_time = parse_time(line, year_dataset)

                if alert_time is None:
                    continue

                possible_lines = log_lines[pos-max_number_of_lines: pos]
                earliest_time = alert_time - timedelta(seconds=max_seconds)
                result = [line for line in possible_lines if alert_time >= parse_time(line, year_dataset) >= earliest_time]
        except FileNotFoundError:
            return "Error: Log file not found"
    return result

def parse_time(log_line, year):
    date_pattern_1 = r'^(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}'
    date_pattern_2 = r'^\[(Mon|Tue|Wed|Thu|Fri|Sat|Sun)\s+(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\.\d+\s+\d{4}\]'
    date_pattern_3 = r'\[(\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2} [+\-]\d{4})\]'
    date_pattern_4 = r'"@timestamp":"([^"]+)"'
    date_pattern_5 = r'audit\((\d+\.\d+):'
    date_pattern_6 = r"""['"]timestamp['"]\s*:\s*['"]([^'"]+)['"]"""
    date_pattern_7 = r'(\d{2}/\d{2}/\d{4}-\d{2}:\d{2}:\d{2}\.\d+)'

    if log_line.startswith(str(year)):
        timestamp_str = " ".join(log_line.split()[:2])
        date = datetime.strptime(timestamp_str, f"%Y-%m-%d %H:%M:%S")
    elif re.match(date_pattern_1, log_line): # Jan 18 12:15:50
        timestamp_str = " ".join(log_line.split()[:3])
        date = datetime.strptime(f"{year} {timestamp_str}", f"%Y %b %d %H:%M:%S")
    elif re.match(date_pattern_2, log_line): # [Tue Jan 18 12:17:27.713538 2022]
        timestamp_str = re.search(r'\[(\w{3} \w{3} \d{1,2} \d{2}:\d{2}:\d{2}\.\d+ \d{4})\]', log_line).group(1)
        date = datetime.strptime(timestamp_str, f"%a %b %d %H:%M:%S.%f %Y")
    elif re.search(date_pattern_3, log_line):
        timestamp_str = re.search(date_pattern_3, log_line).group(1)
        date = datetime.strptime(timestamp_str, f"%d/%b/%Y:%H:%M:%S %z")
    elif re.search(date_pattern_4, log_line):
        timestamp_str = re.search(date_pattern_4, log_line).group(1)
        date = datetime.strptime(timestamp_str, f"%Y-%m-%dT%H:%M:%S.%fZ")
    elif re.search(date_pattern_5, log_line):
        timestamp_str = float(re.search(date_pattern_5, log_line).group(1))
        date = datetime.fromtimestamp(timestamp_str)
    elif re.search(date_pattern_6, log_line): # 'timestamp':'2022-01-18T12:06:41.800120+0000'
        timestamp_str = re.search(date_pattern_6, log_line).group(1)
        date = datetime.strptime(timestamp_str, f"%Y-%m-%dT%H:%M:%S.%f%z")
    elif re.search(date_pattern_7, log_line):
        timestamp_str = re.search(date_pattern_7, log_line).group(1)
        date = datetime.strptime(timestamp_str, f"%m/%d/%Y-%H:%M:%S.%f")
    else:
        print("Unexpected / no time format in alert:" + log_line)
        date = None

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

Additionally, to help with classification there are some log lines from the same log file as the line that triggered the alert:
"""

with open("../llm_keys/gemini.txt", "r") as file:
    os.environ["GEMINI_API_KEY"] = file.read().strip()

class Classification(BaseModel):
    anomaly_timestamp: str
    classification: str
    mitre_technique: list[str]
    description: str

with open(input_file_name, "r") as input_lines:
    with open("./server_ip_mapping.json") as mapping:
        host_ip_mapping = json.load(mapping)
        host_ip_lookup = {item["ip"]: item["hostname"] for item in host_ip_mapping}

    request_stats = []

    for i in range(0,10):
        print(f"\nStarting run with max seconds {(i+1) * 5}")
        max_number_of_seconds = (i + 1) * 5
        additional_log_lines = []
        processed_lines = []

        timestamp = datetime.now().strftime('%d_%m_%Y_%H_%M')
        filename = "./" + input_file_name[:-5].replace("../test_data/LLM/", "../preprocessing_files/add_lines/time/" + str(max_number_of_seconds) + "_run/gemini/") + "_" + timestamp + "_results.json"

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
                ip = line["AMiner"]["ID"]
                raw_data = line["LogData"]["RawLogData"]
                for path in line["LogData"]["LogResources"]:
                    additional_log_lines = getAdditionalLogDataAminer(max_number_of_seconds, path, ip, raw_data, host_ip_lookup)
                    if additional_log_lines == "Error: Log file not found.":
                        result_entry["log_collection_error"] = additional_log_lines
                        additional_log_lines = []
                    if not additional_log_lines:
                        result_entry["log_collection_error"] = "Log file does not contain log line."

            elif dataset == "wazuh":
                path = line["location"]
                if "full_log" in line.keys():
                    raw_data = line["full_log"]
                else:
                    raw_data = line["data"]["timestamp"]

                if "predecoder" in line.keys() and "hostname" in line["predecoder"].keys():
                    host_identifier = line["predecoder"]["hostname"]
                    if host_identifier != "inet-firewall" and host_identifier != "inet-dns":
                        host_identifier = host_identifier.replace("-", "_")
                else:
                    host_identifier = line["agent"]["ip"]

                additional_log_lines = getAdditionalLogDataWazuh(max_number_of_seconds, path, host_identifier, raw_data, host_ip_lookup)
                if additional_log_lines == "Error: Log file not found.":
                    result_entry["log_collection_error"] = additional_log_lines
                    additional_log_lines = []
                if not additional_log_lines:
                    result_entry["log_collection_error"] = "There are no available log lines before the alert."

            runstats.append(
                {
                    "line_nr": j,
                    "nr_add_lines": len(additional_log_lines)
                }
            )

            if len(additional_log_lines) == 0:
                result_entry["output"] = "No request was sent as no additional log lines were available within the time frame."
                processed_lines.append(result_entry)

                with open(filename, "w") as f:
                    json.dump(processed_lines, f, indent=2)

                print("Line number " + str(j) + " processed.")
                time.sleep(2) # break to avoid rate limits
                continue

            working_message += ' '.join([str(line) for line in additional_log_lines])
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
            time.sleep(2) # break to avoid rate limits

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

    request_stats_file = "./" + input_file_name[:-5].replace("../test_data/LLM/", "../preprocessing_files/add_lines/time/") + "_" + timestamp + "_gemini_request_stats.json"
    with open(request_stats_file, "w") as f:
        json.dump(request_stats, f, indent=2)
