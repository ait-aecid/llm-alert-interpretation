import json
from openai import OpenAI
import os
import time
from datetime import datetime
from pydantic import BaseModel
from os import listdir
from os.path import isfile, join
import tiktoken

input_file_name = "../test_data/LLM/wazuh_attack_lines.json"
dataset = "wazuh"

token_limit = 700000
request_limit = 4000
max_output_tok = 1000

def getAdditionalLogDataAminer(number_of_lines, filename, ip, raw_data, mapping):
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

        try:
            with open(log_file_path + file, "r") as log_file:
                log_lines = log_file.readlines()
                log_lines = [x.strip() for x in log_lines]
                pos = len(log_lines) + 100 # out of range

                for i, line in enumerate(log_lines):
                    if line.strip() == raw_data[0]:
                        pos = i
                        line_found = True
                        break

                result = log_lines[pos-number_of_lines: pos]
        except FileNotFoundError:
            return "Error: Log file not found"

    return result

def getAdditionalLogDataWazuh(number_of_lines, filename, host_identifier, raw_data, mapping):
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
                            break
                    elif line.strip() == raw_data:
                        pos = i
                        line_found = True
                        break
                    elif "type=AVC msg=audit(" in line.strip() or "type=SYSCALL msg=audit(" in line.strip() or "type=PROCTITLE msg=audit(" in line.strip():
                        if line.strip() in raw_data:
                            pos = min(i, pos)
                            line_found = True

                result = log_lines[pos-number_of_lines: pos]
        except FileNotFoundError:
            return "Error: Log file not found"
    return result

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

Additionally, to help with classification there are some log lines from the same log file as the line that triggered the alert:
"""

with open("../llm_keys/openai.txt", "r") as file:
    os.environ["OPENAI_API_KEY"] = file.read().strip()

#client = OpenAI()

class Classification(BaseModel):
    anomaly_timestamp: str
    classification: str
    mitre_technique: list[str]
    description: str


with open(input_file_name, "r") as input_lines:
    with open("./server_ip_mapping.json") as mapping:
        host_ip_mapping = json.load(mapping)
        host_ip_lookup = {item["ip"]: item["hostname"] for item in host_ip_mapping}

    for i in range(0,20):
        print(f"\nStarting run {i+1}")
        number_of_lines = i + 1
        additional_log_lines = []
        processed_lines = []

        timestamp = datetime.now().strftime('%d_%m_%Y_%H_%M')
        filename = "./" + input_file_name[:-5].replace("../test_data/LLM/", "../preprocessing_files/add_lines/simple/" + str(number_of_lines) + "_run/chatgpt/") + "_" + timestamp + "_results.json"

        input_lines.seek(0)
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
                    additional_log_lines = getAdditionalLogDataAminer(number_of_lines, path, ip, raw_data, host_ip_lookup)
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

                additional_log_lines = getAdditionalLogDataWazuh(number_of_lines, path, host_identifier, raw_data, host_ip_lookup)
                if additional_log_lines == "Error: Log file not found.":
                    result_entry["log_collection_error"] = additional_log_lines
                    additional_log_lines = []
                if not additional_log_lines:
                    result_entry["log_collection_error"] = "There are no available log lines before the alert."

            working_message += ' '.join([str(line) for line in additional_log_lines])
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
