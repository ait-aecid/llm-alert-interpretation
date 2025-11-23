import json
import re

from openai import OpenAI
from google import genai
from tqdm import tqdm
from datetime import datetime

from anomaly_preprocessing.mode import AnomalyProcessingMode

class AnomalyProcessor:
    ioc_list = list
    ioc_regex_pattern = {}

    def __init__(self, file_exists=False, preprocessing_mode=None):
        self.file_exists = file_exists
        self.preprocessing_mode = preprocessing_mode

    # Preprocessing options
    def _chatgpt_preinterpretation(self, anomalies, inputfile):
        if self.file_exists:
            with open("./preprocessing_files/chatgpt_" + inputfile, "r") as file:
                return json.load(file)
        
        with open("./preprocessing_files/key.txt", "r") as f:
            key = f.read().strip()

        preprocessed = []
        # This part requires OpenAI credits to use
        client = OpenAI(
            api_key = key
        )

        for i in tqdm(range(0, len(anomalies))):
            prompt="I have the following lines of IDS alerts that I would like to analyze. Can you please help me" \
            "with this? Can you please report what type of attack the alert possibly represents (attack_type), the" \
            "MITRE ATT&CK IDs that correspond to the potential attacks (mitre), a description in keywords of why you think " \
            "the line represents the indicated attacks (description) and tools an attacker could use to perform the indicated" \
            "attack (tools). Also please indicate if you think it is a true positive (TP) or a false positive (FP)." \
            "For your response please use the following json format:" \
            "{'anomaly_timestamp': 'timestamp from the anomaly line', 'attack_type': ['attack type 1', 'attack type 2'], " \
            "'mitre': ['ID1', 'ID2'], 'description': 'description why the line shows the attack', 'tools': ['tool1', 'tool2'], " \
            "'classification': 'TP or FP'}. I want all of the lines within one json list in the end. Here are the alert" \
            " lines:" + str(anomalies[i:i+100])

            response = client.chat.completions.create(
                model="gpt-4",
                messages=[
                    {"role": "system", "content": "You are a talented SOC analyst."},
                    {"role": "user", "content": prompt},
                ]
            )
            i = i + 100
            preprocessed.append(response.choices[0].message.content)
        return preprocessed

    def _gemini_preinterpretation(self, anomalies, inputfile):
        if self.file_exists:
            with open("./preprocessing_files/gemini_" + inputfile, "r") as file:
                return json.load(file)
        
        with open("./preprocessing_files/_gemini_key.txt", "r") as f:
            key = f.read().strip()

        preprocessed = []
        # This part requires access to a Gemini API key and a payment plan to use
        client = genai.Client(
            api_key = key
        )

        for i in tqdm(range(0, len(anomalies))):
            prompt="I have the following lines of IDS alerts that I would like to analyze. Can you please help me" \
            "with this? Can you please report what type of attack the alert possibly represents (attack_type), the" \
            "MITRE ATT&CK IDs that correspond to the potential attacks (mitre), a description in keywords of why you think " \
            "the line represents the indicated attacks (description) and tools an attacker could use to perform the indicated" \
            "attack (tools). Also please indicate if you think it is a true positive (TP) or a false positive (FP)." \
            "For your response please use the following json format:" \
            "{'anomaly_timestamp': 'timestamp from the anomaly line', 'attack_type': ['attack type 1', 'attack type 2'], " \
            "'mitre': ['ID1', 'ID2'], 'description': 'description why the line shows the attack', 'tools': ['tool1', 'tool2'], " \
            "'classification': 'TP or FP'}. I want all of the lines within one json list in the end. Here are the alert" \
            " lines:" + str(anomalies[i:i+100])

            response = client.models.generate_content(
                model="gemini-2.0-flash",
                contents=prompt
            )
            i = i + 100
            preprocessed.append(response.text)
        return preprocessed
        
    def _log_line_content_preprocessing(self, log_line):
        with open("./preprocessing_files/anomaly_components.json") as pattern_file:
            anomaly_regexPatterns = json.load(pattern_file)

        found_items = []
        for _, regex_options in anomaly_regexPatterns.items():
            for regex in regex_options:
                match_iter = re.finditer(regex, log_line) # iterator over all non-overlapping matches in string
                for match in match_iter:
                    found_items.append(match.group())

        # Remove duplicates
        found_items = list(set(found_items))
        found_items.sort(key=len, reverse=True)

        for item in found_items:
            log_line = log_line.replace(item, "")

        cleaned = log_line.replace('\\"', '')  
        cleaned = cleaned.replace('"', '')
        cleaned = cleaned.replace('[', ' ')
        cleaned = cleaned.replace(']', ' ')
        tokens = cleaned.split()
        tokens_more_than_2_chars = [token for token in tokens if len(token) >= 3]

        return found_items + tokens_more_than_2_chars

    # Input parsing
    def anomaly_to_intermediate(self, anomaly, additional_info=None):
        match (self.preprocessing_mode):
            case AnomalyProcessingMode.FULL_TEXT:
                with open(additional_info) as config:
                    availableFields = json.load(config)

                    anomaly_fields = {}
                    for key, val in availableFields.items():
                        if key == "timestamp" and "timestamp_format" in availableFields.keys():
                            continue

                        if key == "timestamp_format":
                            field = availableFields["timestamp"][0]
                            anomaly_fields[key] = str(datetime.strptime(json.loads(anomaly)[field], val[0]).timestamp())
                            continue
        
                        value_backup = ""
                        for element in val:
                            levels = element.split(".")
                            value = json.loads(anomaly)

                            for level in levels:
                                if level not in value.keys():
                                    continue
                                value = value[level]
                            
                            if type(value) == str:
                                value_backup += value
                            if type(value) == dict:
                                for k, v in value.items():
                                    value_backup += " " + v
                            if type(value) == list:
                                value_backup += " ".join(str(v) for v in value)

                        anomaly_fields[key] = value_backup

                        if key == "logLineContent":
                            value = anomaly_fields[key]
                            anomaly_fields[key] = self._log_line_content_preprocessing(value)

                        if key == "description":
                            anomaly_fields[key] = anomaly_fields[key].replace("AMiner: ", "")
                return anomaly_fields
            
            case AnomalyProcessingMode.CHATGPT:
                return self._chatgpt_preinterpretation(anomaly, additional_info)
            
            case AnomalyProcessingMode.GEMINI:
                return self._gemini_preinterpretation(anomaly, additional_info)