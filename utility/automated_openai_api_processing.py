import json
from openai import OpenAI
import os
import time
from datetime import datetime
from pydantic import BaseModel

input_file_name = "../test_data/LLM/aminer_attack_lines.json"
dataset = "zero"

# System message
if dataset == "zero":
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
    - Use short but precise description"""
elif dataset == "aminer_one":
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

    ### Few-shot Examples:
    Example 1:
    ids_line:
    {"AnalysisComponent": {"AnalysisComponentIdentifier": 3, "AnalysisComponentType": "NewMatchPathDetector", "AnalysisComponentName": "AMiner: New event type.", "Message": "New path(es) detected", "PersistenceFileName": "nmpd", "TrainingMode": false, "AffectedLogAtomPaths": ["/model/fm/start/remainder"]}, "LogData": {"RawLogData": ["2022-01-17 11:21:44 TLS error on connection from vpn.smith.santos.com [172.21.128.119] (gnutls_handshake): An unexpected TLS packet was received."], "Timestamps": [1642418504], "DetectionTimestamp": [1642418504], "LogLinesCount": 1, "LogResources": ["/var/log/exim4/mainlog"]}, "AMiner": {"ID": "172.21.131.50"}}

    Output:
    {
        "anomaly_timestamp": "1642418504",
        "classification": "TP",
        "mitre_technique": ["Active Scanning: Wordlist Scanning", "Network Service Discovery"],
        "description": "The alert shows an unexpected TLS handshake error from a VPN service, consistent with scanning that is probing what services and protocols are listening."
    }

    Example 2:
    ids_line:
    {"AnalysisComponent": {"AnalysisComponentIdentifier": 5, "AnalysisComponentType": "NewMatchPathValueDetector", "AnalysisComponentName": "AMiner: New request method in Apache Access log.", "Message": "New value(s) detected", "PersistenceFileName": "nmpvd_request_method", "TrainingMode": false, "AffectedLogAtomPaths": ["/model/fm/request/method"], "AffectedLogAtomValues": ["3"]}, "LogData": {"RawLogData": ["172.21.128.119 - - [17/Jan/2022:11:22:24 +0000] \"HEAD /robots.txt HTTP/1.1\" 404 146 \"https://intranet.smith.santos.com\" \"WPScan v3.8.20 (https://wpscan.com/wordpress-security-scanner)\""], "Timestamps": [1642418544], "DetectionTimestamp": [1642418544], "LogLinesCount": 1, "LogResources": ["/var/log/apache2/intranet-access.log"]}, "AMiner": {"ID": "192.168.104.155"}}

    Output:
    {
        "anomaly_timestamp": "1642418544",
        "classification": "TP",
        "mitre_technique": ["Active Scanning: Vulnerability Scanning", "Gather Victim Host Information: Software"],
        "description": "The alert indicates the use of an automated scanner to probe and map weaknesses in the WordPress application."
    }

    Example 3:
    ids_line:
    {"AnalysisComponent": {"AnalysisComponentIdentifier": 4, "AnalysisComponentType": "NewMatchPathValueDetector", "AnalysisComponentName": "AMiner: New status code in Apache Access log.", "Message": "New value(s) detected", "PersistenceFileName": "nmpvd_status_code", "TrainingMode": false, "AffectedLogAtomPaths": ["/model/status_code"], "AffectedLogAtomValues": ["403"]}, "LogData": {"RawLogData": ["172.21.128.119 - - [17/Jan/2022:11:22:02 +0000] \"GET /.htpasswd_ HTTP/1.1\" 403 366 \"-\" \"Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)\""], "Timestamps": [1642418522], "DetectionTimestamp": [1642418522], "LogLinesCount": 1, "LogResources": ["/var/log/apache2/intranet-access.log"]}, "AMiner": {"ID": "192.168.104.155"}}

    Output:
    {
        "anomaly_timestamp": "1642418522",
        "classification": "TP",
        "mitre_technique": ["Active Scanning: Wordlist Scanning"],
        "description": "The alert shows attempted access to a sensitive file (.htpasswd_) and therefore indicates probing. The _ indicates automated scanning because of the slightly changes spelling of a common file."
    }

    Example 4:
    ids_line:
    {"AnalysisComponent": {"AnalysisComponentIdentifier": 6, "AnalysisComponentType": "EntropyDetector", "AnalysisComponentName": "AMiner: High entropy in Apache Access request.", "Message": "Value entropy anomaly detected", "PersistenceFileName": "entropy_request", "TrainingMode": false, "AffectedLogAtomPaths": ["/model/fm/request/request"], "AffectedLogAtomValues": ["/wp-content/uploads/2022/01/yvmuplzucm-1642418578.1653.php?wp_meta=WyJteXNxbCIsICItdSIsICJ3b3JkcHJlc3MiLCAiLXB0YWlub294M2FlZGVlU2giLCAid29yZHByZXNzX2RiIiwgIi1lIiwgIlwic2VsZWN0ICogZnJvbSB3cF91c2Vyc1wiIl0%3D"], "CriticalValue": 0.038245009174066216, "ProbabilityThreshold": 0.05}, "LogData": {"RawLogData": ["172.21.128.119 - - [17/Jan/2022:11:24:14 +0000] \"GET /wp-content/uploads/2022/01/yvmuplzucm-1642418578.1653.php?wp_meta=WyJteXNxbCIsICItdSIsICJ3b3JkcHJlc3MiLCAiLXB0YWlub294M2FlZGVlU2giLCAid29yZHByZXNzX2RiIiwgIi1lIiwgIlwic2VsZWN0ICogZnJvbSB3cF91c2Vyc1wiIl0%3D HTTP/1.1\" 200 507755 \"-\" \"python-requests/2.27.1\""], "Timestamps": [1642418654], "DetectionTimestamp": [1642418654], "LogLinesCount": 1, "LogResources": ["/var/log/apache2/intranet-access.log"]}, "AMiner": {"ID": "192.168.104.155"}}

    Output:
    {
        "anomaly_timestamp": "1642418654",
        "classification": "TP",
        "mitre_technique": ["Server Software Component: Web Shell"],
        "description": "The high-entropy request is invoking a suspicious PHP file upload with encoded parameters, strongly indicating web shell interaction over HTTP."
    }

    Example 5:
    ids_line:
    {"AnalysisComponent": {"AnalysisComponentIdentifier": 6, "AnalysisComponentType": "EntropyDetector", "AnalysisComponentName": "AMiner: High entropy in Apache Access request.", "Message": "Value entropy anomaly detected", "PersistenceFileName": "entropy_request", "TrainingMode": false, "AffectedLogAtomPaths": ["/model/fm/request/request"], "AffectedLogAtomValues": ["/wp-content/uploads/2022/01/yvmuplzucm-1642418578.1653.php?wp_meta=WyJ3Z2V0IiwgImh0dHBzOi8vZ2l0aHViLmNvbS9haXQtYWVjaWQvd3BoYXNoY3JhY2svYXJjaGl2ZS9yZWZzL3RhZ3MvdjAuMS50YXIuZ3oiXQ%3D%3D"], "CriticalValue": 0.04084936760975996, "ProbabilityThreshold": 0.05}, "LogData": {"RawLogData": ["172.21.128.119 - - [17/Jan/2022:11:24:16 +0000] \"GET /wp-content/uploads/2022/01/yvmuplzucm-1642418578.1653.php?wp_meta=WyJ3Z2V0IiwgImh0dHBzOi8vZ2l0aHViLmNvbS9haXQtYWVjaWQvd3BoYXNoY3JhY2svYXJjaGl2ZS9yZWZzL3RhZ3MvdjAuMS50YXIuZ3oiXQ%3D%3D HTTP/1.1\" 200 506723 \"-\" \"python-requests/2.27.1\""], "Timestamps": [1642418656], "DetectionTimestamp": [1642418656], "LogLinesCount": 1, "LogResources": ["/var/log/apache2/intranet-access.log"]}, "AMiner": {"ID": "192.168.104.155"}}

    Output:
    {
        "anomaly_timestamp": "1642418656",
        "classification": "TP",
        "mitre_technique": ["Server Software Component: Web Shell", "Brute Force: Password Cracking"],
        "description": "The high-entropy request to an uploaded PHP file (web shell) includes encoded parameters that trigger downloading and use of a password-cracking tool targeting WordPress credentials."
    }

    Example 6:
    ids_line:
    {"AnalysisComponent": {"AnalysisComponentIdentifier": 6, "AnalysisComponentType": "EntropyDetector", "AnalysisComponentName": "AMiner: High entropy in Apache Access request.", "Message": "Value entropy anomaly detected", "PersistenceFileName": "entropy_request", "TrainingMode": false, "AffectedLogAtomPaths": ["/model/fm/request/request"], "AffectedLogAtomValues": ["/wp-content/uploads/2022/01/yvmuplzucm-1642418578.1653.php?wp_meta=WyJiYXNoIiwgIi1jIiwgIiAnMDwmMTk2O2V4ZWMgMTk2PD4vZGV2L3RjcC8xMC4yMjkuMi4yMTYvMTY0ODY7IHNoIDwmMTk2ID4mMTk2IDI%2BJjE5NiciLCAiJiJd"], "CriticalValue": 0.04595989988386346, "ProbabilityThreshold": 0.05}, "LogData": {"RawLogData": ["172.21.128.119 - - [17/Jan/2022:11:58:04 +0000] \"GET /wp-content/uploads/2022/01/yvmuplzucm-1642418578.1653.php?wp_meta=WyJiYXNoIiwgIi1jIiwgIiAnMDwmMTk2O2V4ZWMgMTk2PD4vZGV2L3RjcC8xMC4yMjkuMi4yMTYvMTY0ODY7IHNoIDwmMTk2ID4mMTk2IDI%2BJjE5NiciLCAiJiJd HTTP/1.1\" 200 506723 \"-\" \"python-requests/2.27.1\""], "Timestamps": [1642420684], "DetectionTimestamp": [1642420684], "LogLinesCount": 1, "LogResources": ["/var/log/apache2/intranet-access.log"]}, "AMiner": {"ID": "192.168.104.155"}}

    Output:
    {
        "anomaly_timestamp": "1642420684",
        "classification": "TP",
        "mitre_technique": ["Command and Scripting Interpreter: Unix Shell"],
        "description": "The alert shows an attacker exploiting a vulnerable PHP upload to deliver and execute a high-entropy bash reverse shell."
    }

    Example 7:
    ids_line:
    {"AnalysisComponent": {"AnalysisComponentIdentifier": 3, "AnalysisComponentType": "NewMatchPathDetector", "AnalysisComponentName": "AMiner: New event type.", "Message": "New path(es) detected", "PersistenceFileName": "nmpd", "TrainingMode": false, "AffectedLogAtomPaths": ["/model/service/su", "/model/service/su/systemd_str", "/model/service/su/id", "/model/service/su/brack_str2", "/model/service/su/fm/seq", "/model/service/su/fm/seq/brack_str", "/model/service/su/fm/seq/user", "/model/service/su/fm/seq/by_str", "/model/service/su/fm/seq/su_user"]}, "LogData": {"RawLogData": ["Jan 17 11:58:17 intranet-server su[20749]: Successful su for gmorgan by www-data"], "Timestamps": [1642420697], "DetectionTimestamp": [1642420697], "LogLinesCount": 1, "LogResources": ["/var/log/auth.log"]}, "AMiner": {"ID": "192.168.104.155"}}

    Output:
    {
        "anomaly_timestamp": "1642420697",
        "classification": "TP",
        "mitre_technique": ["Valid Accounts"],
        "description": "The alert shows the www-data process successfully using su to switch to the user gmorgan, indicating potential abuse of legitimate credentials for privilege escalation"
    }

    Example 8:
    ids_line:
    {"AnalysisComponent": {"AnalysisComponentIdentifier": 32, "AnalysisComponentType": "EventCountClusterDetector", "AnalysisComponentName": "AMiner: Unusual occurrence frequencies of DNS log events.", "Message": "Frequency anomaly detected", "PersistenceFileName": "eccd_dns", "TrainingMode": true, "AffectedLogAtomPaths": [], "AffectedLogAtomValues": [["/model", "/model/time", "/model/service", "/model/br_open", "/model/pid", "/model/br_close", "/model/type/query", "/model/type/query/query", "/model/type/query/record", "/model/type/query/br_close", "/model/type/query/domain", "/model/type/query/from", "/model/type/query/ip"], ["/model", "/model/time", "/model/service", "/model/br_open", "/model/pid", "/model/br_close", "/model/type/forwarded", "/model/type/forwarded/reply", "/model/type/forwarded/domain", "/model/type/forwarded/to", "/model/type/forwarded/ip"], ["/model", "/model/time", "/model/service", "/model/br_open", "/model/pid", "/model/br_close", "/model/type/nameserver", "/model/type/nameserver/nameserver", "/model/type/nameserver/ip", "/model/type/nameserver/refused"], ["/model", "/model/time", "/model/service", "/model/br_open", "/model/pid", "/model/br_close", "/model/type/reply", "/model/type/reply/reply", "/model/type/reply/domain", "/model/type/reply/is", "/model/type/reply/ip"]], "AffectedLogAtomFrequencies": [3, 3, 1, 5], "AffectedIdValues": []}, "CountData": {"ConfidenceFactor": 0.5, "Confidence": 0.9395604395604396}, "LogData": {"RawLogData": ["Jan 20 22:31:12 dnsmasq[14755]: query[A] intranet.hurstwong.wardbeck.info from 172.21.240.147"], "Timestamps": [1642717872], "DetectionTimestamp": [1642717872], "LogLinesCount": 1, "LogResources": ["/var/log/dnsmasq.log"]}, "AMiner": {"ID": "10.132.56.1"}}

    Output:
    {
        "anomaly_timestamp": "1642717872",
        "classification": "TP",
        "mitre_technique": ["Exfiltration Over C2 Channel"],
        "description": "The unusual DNS query frequencies indicate data is being covertly sent out of the network."
    }

    Example 9:
    ids_line:
    {"AnalysisComponent": {"AnalysisComponentIdentifier": 34, "AnalysisComponentType": "EventCountClusterDetector", "AnalysisComponentName": "AMiner: Unusual occurrence frequencies of DNS query records.", "Message": "Frequency anomaly detected", "PersistenceFileName": "eccd_dns_record", "TrainingMode": true, "AffectedLogAtomPaths": ["/model/type/query/record"], "AffectedLogAtomValues": [["A"], ["SRV"], ["AAAA"], ["TXT"]], "AffectedLogAtomFrequencies": [262, 35, 31, 8], "AffectedIdValues": []}, "CountData": {"ConfidenceFactor": 0.3, "Confidence": 1}, "LogData": {"RawLogData": ["Jan 14 01:00:19 dnsmasq[14569]: query[A] 3x6-.633-.SM0QTCnaOLcx7xgL9vNFI0KXyPr/Xkc72Nd0DAz4/tbZQhFsb0v7/WA2o/4S-.Ro6LF8Lt02nJ4nyIZAM7dtmRjt3QOa/heoL/X/Kfhx7RDBgcmV53Dk4oYVMD-.8UV99PJ3z92*/9qeVTL5vSbvquEDtqRHxG48z8LBQ29x77qf5QPpT0szMM4N-.customers_2013.xlsx.kiirjekuimkpcrcioastvkeodpnimx.biz from 10.229.0.4"], "Timestamps": [1642122019], "DetectionTimestamp": [1642122019], "LogLinesCount": 1, "LogResources": ["/var/log/dnsmasq.log"]}, "AMiner": {"ID": "10.229.255.254"}}

    Output:
    {
        "anomaly_timestamp": "1642122019",
        "classification": "FP",
        "mitre_technique": [],
        "description": "The alert is likely a false positive because the training mode is still active, the detection confidence is low and no repeated suspicious behavior."
    }
    """
elif dataset == "wazuh_one":
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

    ### Few-shot Examples:
    Example 1:
    ids_line:
    Input (IDS anomaly line):
    {"agent": {"ip": "10.229.0.4", "name": "wazuh-client", "id": "30"}, "manager": {"name": "wazuh.manager"}, "data": {"metadata": {"flowints": {"tls": {"anomaly": {"count": "2"}}}}, "tx_id": "0", "app_proto": "tls", "in_iface": "ens3", "src_ip": "54.173.41.153", "src_port": "443", "event_type": "alert", "alert": {"severity": "3", "signature_id": "2230003", "rev": "1", "gid": "1", "signature": "SURICATA TLS invalid handshake message", "action": "allowed", "category": "Generic Protocol Command Decode"}, "flow_id": "1319969355864039.000000", "dest_ip": "10.229.0.4", "proto": "TCP", "tls": {"version": "UNDETERMINED", "ja3": {"string": "771,4865-4867-4866-49195-49199-52393-52392-49196-49200-49162-49161-49171-49172-156-157-47-53-10,0-23-65281-10-11-16-5-51-43-13-28-21,29-23-24-25-256-257,0", "hash": "a75de44db3e351bbd8d38b64c41f444e"}, "sni": "ping.chartbeat.net"}, "dest_port": "58774", "flow": {"pkts_toserver": "7", "start": "2022-01-17T11:18:42.923623+0000", "bytes_toclient": "257", "bytes_toserver": "1830", "pkts_toclient": "3"}, "timestamp": "2022-01-17T11:18:43.274160+0000"}, "rule": {"firedtimes": 9, "mail": false, "level": 3, "description": "Suricata: Alert - SURICATA TLS invalid handshake message", "groups": ["ids", "suricata"], "id": "86601"}, "decoder": {"name": "json"}, "input": {"type": "log"}, "@timestamp": "2022-01-17T11:18:43.274160Z", "location": "/var/log/suricata/eve.json", "id": "1687475310.10001877"}

    Output:
    {
        "anomaly_timestamp": "2022-01-17T11:18:43.274160Z",
        "classification": "TP",
        "mitre_technique": ["Network Service Discovery", "Active Scanning: Vulnerability Scanning"],
        "description": "The alert reflects unusual TLS handshakes that could indicate reconnaissance activity probing services"
    }

    Example 2:
    ids_line:
    {"agent": {"ip": "192.168.104.155", "name": "wazuh-client", "id": "26"}, "manager": {"name": "wazuh.manager"}, "data": {"protocol": "POST", "srcip": "172.21.128.119", "id": "404", "url": "/sdk"}, "rule": {"firedtimes": 9, "mail": false, "level": 5, "pci_dss": ["6.5", "11.4"], "tsc": ["CC6.6", "CC7.1", "CC8.1", "CC6.1", "CC6.8", "CC7.2", "CC7.3"], "description": "Web server 400 error code.", "groups": ["web", "accesslog", "attack"], "id": "31101", "nist_800_53": ["SA.11", "SI.4"], "gdpr": ["IV_35.7.d"]}, "decoder": {"name": "web-accesslog"}, "full_log": "172.21.128.119 - - [17/Jan/2022:11:21:46 +0000] \"POST /sdk HTTP/1.1\" 404 3269 \"-\" \"Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)\"", "input": {"type": "log"}, "@timestamp": "2022-01-17T11:21:46.000000Z", "location": "/var/log/apache2/intranet-access.log", "id": "1687475492.10116645"}

    Output:
    {
        "anomaly_timestamp": "2022-01-17T11:21:46.000000Z",
        "classification": "TP",
        "mitre_technique": ["Network Service Discovery", "Active Scanning: Vulnerability Scanning"],
        description": "The HTTP POST request resulting in a 404 from Nmap Scripting Engine indicates reconnaissance activity"
    }

    Example 3:
    ids_line:
    {"agent": {"ip": "192.168.104.155", "name": "wazuh-client", "id": "26"}, "manager": {"name": "wazuh.manager"}, "data": {"protocol": "HEAD", "srcip": "172.21.128.119", "id": "404", "url": "/wp-content/backup-db/"}, "rule": {"firedtimes": 4146, "mail": false, "level": 5, "pci_dss": ["6.5", "11.4"], "tsc": ["CC6.6", "CC7.1", "CC8.1", "CC6.1", "CC6.8", "CC7.2", "CC7.3"], "description": "Web server 400 error code.", "groups": ["web", "accesslog", "attack"], "id": "31101", "nist_800_53": ["SA.11", "SI.4"], "gdpr": ["IV_35.7.d"]}, "decoder": {"name": "web-accesslog"}, "full_log": "172.21.128.119 - - [17/Jan/2022:11:22:24 +0000] \"HEAD /wp-content/backup-db/ HTTP/1.1\" 404 146 \"https://intranet.smith.santos.com\" \"WPScan v3.8.20 (https://wpscan.com/wordpress-security-scanner)\"", "input": {"type": "log"}, "@timestamp": "2022-01-17T11:22:24.000000Z", "location": "/var/log/apache2/intranet-access.log", "id": "1687475530.13015899"}

    Output:
    {
        "anomaly_timestamp": "2022-01-17T11:22:24.000000Z",
        "classification": "TP",
        "mitre_technique": ["Active Scanning: Vulnerability Scanning"],
        "description": "The alert shows WPScan actively probing a WordPress site for exposed backup files which indicates active scanning as long as no pentesing is going on within the organisation."
    }

    Example 4:
    ids_line:
    {"agent": {"ip": "192.168.104.155", "name": "wazuh-client", "id": "26"}, "manager": {"name": "wazuh.manager"}, "data": {"protocol": "GET", "srcip": "172.21.128.119", "id": "403", "url": "/.htpasswd_"}, "rule": {"firedtimes": 27, "mail": false, "level": 5, "pci_dss": ["6.5", "11.4"], "tsc": ["CC6.6", "CC7.1", "CC8.1", "CC6.1", "CC6.8", "CC7.2", "CC7.3"], "description": "Web server 400 error code.", "groups": ["web", "accesslog", "attack"], "id": "31101", "nist_800_53": ["SA.11", "SI.4"], "gdpr": ["IV_35.7.d"]}, "decoder": {"name": "web-accesslog"}, "full_log": "172.21.128.119 - - [17/Jan/2022:11:22:02 +0000] \"GET /.htpasswd_ HTTP/1.1\" 403 366 \"-\" \"Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)\"", "input": {"type": "log"}, "@timestamp": "2022-01-17T11:22:02.000000Z", "location": "/var/log/apache2/intranet-access.log", "id": "1687475508.10215310"}

    Output:
    {
        "anomaly_timestamp": "2022-01-17T11:22:02.000000Z",
        "classification": "TP",
        "mitre_technique": ["Active Scanning: Vulnerability Scanning"],
        "description": "There is a request attempting to access the sensitive .htpasswd file on a web server which indicates scanning."
    }

    Example 5:
    ids_line:
    {"agent": {"ip": "192.168.104.155", "name": "wazuh-client", "id": "26"}, "manager": {"name": "wazuh.manager"}, "data": {"metadata": {"flowints": {"http": {"anomaly": {"count": "1"}}}}, "tx_id": "1", "app_proto": "http", "in_iface": "ens3", "src_ip": "10.229.2.216", "src_port": "80", "event_type": "alert", "alert": {"severity": "3", "signature_id": "2221010", "rev": "1", "gid": "1", "signature": "SURICATA HTTP unable to match response to request", "action": "allowed", "category": "Generic Protocol Command Decode"}, "flow_id": "1814861280913956.000000", "dest_ip": "192.168.104.155", "proto": "TCP", "http": {"length": "363896", "http_port": "0", "url": "/libhtp::request_uri_not_seen"}, "dest_port": "44636", "flow": {"pkts_toserver": "38", "start": "2022-01-17T11:24:39.469540+0000", "bytes_toclient": "5996", "bytes_toserver": "2666", "pkts_toclient": "6"}, "timestamp": "2022-01-17T11:24:39.481507+0000"}, "rule": {"firedtimes": 90, "mail": false, "level": 3, "description": "Suricata: Alert - SURICATA HTTP unable to match response to request", "groups": ["ids", "suricata"], "id": "86601"}, "decoder": {"name": "json"}, "input": {"type": "log"}, "@timestamp": "2022-01-17T11:24:39.481507Z", "location": "/var/log/suricata/eve.json", "id": "1687475666.15573167"}

    Output:
    {
        "anomaly_timestamp": "2022-01-17T11:24:39.481507Z",
        "classification": "TP",
        "mitre_technique": ["Brute Force: Password Guessing"],
        "description": "The alert shows HTTP traffic anomalies which might be generated because of repeated password attempts."
    }

    Example 6:
    ids_line:
    {"predecoder": {"hostname": "intranet-server", "program_name": "su", "timestamp": "Jan 17 11:58:17"}, "agent": {"ip": "192.168.104.155", "name": "wazuh-client", "id": "26"}, "manager": {"name": "wazuh.manager"}, "data": {"srcuser": "www", "dstuser": "data:gmorgan"}, "rule": {"mail": false, "level": 3, "pci_dss": ["10.2.5"], "hipaa": ["164.312.b"], "tsc": ["CC6.8", "CC7.2", "CC7.3"], "description": "User successfully changed UID.", "groups": ["syslog", "su", "authentication_success"], "nist_800_53": ["AU.14", "AC.7"], "gdpr": ["IV_35.7.d", "IV_32.2"], "firedtimes": 1, "mitre": {"technique": ["Valid Accounts"], "id": ["T1078"], "tactic": ["Defense Evasion", "Persistence", "Privilege Escalation", "Initial Access"]}, "id": "5304", "gpg13": ["7.6", "7.8"]}, "decoder": {"parent": "su", "name": "su"}, "full_log": "Jan 17 11:58:17 intranet-server su[20749]: + /dev/pts/1 www-data:gmorgan", "input": {"type": "log"}, "@timestamp": "2022-01-17T11:58:17.000000Z", "location": "/var/log/auth.log", "id": "1687477683.16223775"}

    Output:
    {
        "anomaly_timestamp": "2022-01-17T11:58:17.000000Z",
        "classification": "TP",
        "mitre_technique": ["Valid Accounts"],
        "description": "The alert shows a successful user switch (su) demonstrating use of legitimate credentials to escalate privileges."
    }

    Example 7:
    ids_line:
    {"agent": {"ip": "10.132.56.1", "name": "wazuh-client", "id": "30"}, "manager": {"name": "wazuh.manager"}, "data": {"metadata": {"flowints": {"tls": {"anomaly": {"count": "2"}}}}, "tx_id": "0", "app_proto": "tls", "in_iface": "ens3", "src_ip": "34.213.76.57", "src_port": "443", "event_type": "alert", "alert": {"severity": "3", "signature_id": "2230003", "rev": "1", "gid": "1", "signature": "SURICATA TLS invalid handshake message", "action": "allowed", "category": "Generic Protocol Command Decode"}, "flow_id": "1981255141899576.000000", "dest_ip": "192.168.96.4", "proto": "TCP", "tls": {"version": "UNDETERMINED", "ja3": {"string": "771,4865-4867-4866-49195-49199-52393-52392-49196-49200-49162-49161-49171-49172-156-157-47-53-10,0-23-65281-10-11-35-16-5-51-43-13-45-28-21,29-23-24-25-256-257,0", "hash": "aa7744226c695c0b2e440419848cf700"}, "sni": "shavar.services.mozilla.com"}, "dest_port": "39008", "flow": {"pkts_toserver": "6", "start": "2022-01-20T22:57:53.539960+0000", "bytes_toclient": "257", "bytes_toserver": "2198", "pkts_toclient": "3"}, "timestamp": "2022-01-20T22:57:54.110943+0000"}, "rule": {"firedtimes": 1, "mail": false, "level": 3, "description": "Suricata: Alert - SURICATA TLS invalid handshake message", "groups": ["ids", "suricata"], "id": "86601"}, "decoder": {"name": "json"}, "input": {"type": "log"}, "@timestamp": "2022-01-20T22:57:54.110943Z", "location": "/var/log/suricata/eve.json", "id": "1688540918.2845670"}

    Output:
    {
        "anomaly_timestamp": "2022-01-20T22:57:54.110943Z",
        "classification": "TP",
        "mitre_technique": ["Exfiltration Over C2 Channel"],
        "description": "The alert indicates exfiltration over C2 channel because the detected invalid TLS handshake likely represents DNS tunneling data over TLS to exfiltrate sensitive information."
    }

    Example 8:
    ids_line:
    {"predecoder": {"hostname": "mail", "program_name": "dovecot", "timestamp": "Jan 14 05:24:34"}, "agent": {"ip": "172.21.131.50", "name": "wazuh-client", "id": "22"}, "manager": {"name": "wazuh.manager"}, "rule": {"mail": false, "level": 3, "pci_dss": ["10.2.5"], "hipaa": ["164.312.b"], "tsc": ["CC6.8", "CC7.2", "CC7.3"], "description": "Dovecot Authentication Success.", "groups": ["dovecot", "authentication_success"], "nist_800_53": ["AU.14", "AC.7"], "gdpr": ["IV_32.2"], "firedtimes": 1, "mitre": {"technique": ["Valid Accounts"], "id": ["T1078"], "tactic": ["Defense Evasion", "Persistence", "Privilege Escalation", "Initial Access"]}, "id": "9701", "gpg13": ["7.1", "7.2"]}, "decoder": {"parent": "dovecot", "name": "dovecot"}, "full_log": "Jan 14 05:24:34 mail dovecot: imap-login: Login: user=<danny.jarvis>, method=PLAIN, rip=172.21.131.50, lip=172.21.131.50, mpid=7889, TLS, session=<RvV0BITVsNqsFYMy>", "input": {"type": "log"}, "@timestamp": "2022-01-14T05:24:34.000000Z", "location": "/var/log/mail.info", "id": "1687194860.7620703"}

    Output:
    {
        "anomaly_timestamp": "2022-01-14T05:24:34.000000Z",
        "classification": "FP",
        "mitre_technique": [],
        "description": "This alert is a false positive because it's a normal, successful login by a legitimate internal user over TLS"
    }
    """
elif dataset == "aminer_two":
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

    ### Few-shot Examples:
    Example 1:
    ids_line:
    {"AnalysisComponent": {"AnalysisComponentIdentifier": 3, "AnalysisComponentType": "NewMatchPathDetector", "AnalysisComponentName": "AMiner: New event type.", "Message": "New path(es) detected", "PersistenceFileName": "nmpd", "TrainingMode": false, "AffectedLogAtomPaths": ["/model/fm/start/remainder"]}, "LogData": {"RawLogData": ["2022-01-17 11:21:44 TLS error on connection from vpn.smith.santos.com [172.21.128.119] (gnutls_handshake): An unexpected TLS packet was received."], "Timestamps": [1642418504], "DetectionTimestamp": [1642418504], "LogLinesCount": 1, "LogResources": ["/var/log/exim4/mainlog"]}, "AMiner": {"ID": "172.21.131.50"}}

    Output:
    {
        "anomaly_timestamp": "1642418504",
        "classification": "TP",
        "mitre_technique": ["Active Scanning: Wordlist Scanning", "Network Service Discovery"],
        "description": "The alert shows an unexpected TLS handshake error from a VPN service, consistent with scanning that is probing what services and protocols are listening."
    }

    Example 2:
    ids_line:
    {"AnalysisComponent": {"AnalysisComponentIdentifier": 3, "AnalysisComponentType": "NewMatchPathDetector", "AnalysisComponentName": "AMiner: New event type.", "Message": "New path(es) detected", "PersistenceFileName": "nmpd", "TrainingMode": false, "AffectedLogAtomPaths": ["/model/service/dovecot/imap/imap_login/login/disconnected_str/auth/no_auth_str", "/model/service/dovecot/imap/imap_login/login/disconnected_str/user_info/handshaking/seq", "/model/service/dovecot/imap/imap_login/login/disconnected_str/user_info/handshaking/seq/handshaking_str", "/model/service/dovecot/imap/imap_login/login/disconnected_str/user_info/handshaking/seq/msg"]}, "LogData": {"RawLogData": ["Jan 17 11:21:38 mail dovecot: imap-login: Disconnected (no auth attempts in 6 secs): user=<>, rip=172.21.128.119, lip=172.21.131.50, TLS handshaking: SSL_accept() failed: error:1417D18C:SSL routines:tls_process_client_hello:version too low, session=<7+cvW8XVqoWsFYB3>"], "Timestamps": [1642418498], "DetectionTimestamp": [1642418498], "LogLinesCount": 1, "LogResources": ["/var/log/mail.log"]}, "AMiner": {"ID": "172.21.131.50"}}

    Output:
    {
        "anomaly_timestamp": "1642418498",
        "classification": "TP",
        "mitre_technique": ["Active Scanning", "Network Service Discovery"],
        "description": "The alert indicates a repeated client IMAP service connation approach without authenticating and failing TLS negotiation due to an unsupported version, which aligns with probing for available services and protocol versions"
    }

    Example 3:
    ids_line:
    {"AnalysisComponent": {"AnalysisComponentIdentifier": 5, "AnalysisComponentType": "NewMatchPathValueDetector", "AnalysisComponentName": "AMiner: New request method in Apache Access log.", "Message": "New value(s) detected", "PersistenceFileName": "nmpvd_request_method", "TrainingMode": false, "AffectedLogAtomPaths": ["/model/fm/request/method"], "AffectedLogAtomValues": ["3"]}, "LogData": {"RawLogData": ["172.21.128.119 - - [17/Jan/2022:11:22:24 +0000] \"HEAD /robots.txt HTTP/1.1\" 404 146 \"https://intranet.smith.santos.com\" \"WPScan v3.8.20 (https://wpscan.com/wordpress-security-scanner)\""], "Timestamps": [1642418544], "DetectionTimestamp": [1642418544], "LogLinesCount": 1, "LogResources": ["/var/log/apache2/intranet-access.log"]}, "AMiner": {"ID": "192.168.104.155"}}

    Output:
    {
        "anomaly_timestamp": "1642418544",
        "classification": "TP",
        "mitre_technique": ["Active Scanning: Vulnerability Scanning", "Gather Victim Host Information: Software"],
        "description": "The alert indicates the use of an automated scanner to probe and map weaknesses in the WordPress application."
    }

    Example 4:
    ids_line:
    {"AnalysisComponent": {"AnalysisComponentIdentifier": 5, "AnalysisComponentType": "NewMatchPathValueDetector", "AnalysisComponentName": "AMiner: New request method in Apache Access log.", "Message": "New value(s) detected", "PersistenceFileName": "nmpvd_request_method", "TrainingMode": false, "AffectedLogAtomPaths": ["/model/fm/request/method"], "AffectedLogAtomValues": ["3"]}, "LogData": {"RawLogData": ["172.21.128.119 - - [17/Jan/2022:11:22:41 +0000] \"HEAD /wp-content/plugins/ecobiz/timthumb.php HTTP/1.1\" 404 146 \"https://intranet.smith.santos.com\" \"WPScan v3.8.20 (https://wpscan.com/wordpress-security-scanner)\""], "Timestamps": [1642418561], "DetectionTimestamp": [1642418561], "LogLinesCount": 1, "LogResources": ["/var/log/apache2/intranet-access.log"]}, "AMiner": {"ID": "192.168.104.155"}}

    Output:
    {
        "anomaly_timestamp": "1642418561",
        "classification": "TP",
        "mitre_technique": ["Active Scanning: Vulnerability Scanning", "Gather Victim Host Information: Software"],
        "description": "The alert indicates the use of an automated scanner to probe and map weaknesses in the WordPress application."
    }

    Example 5:
    ids_line:
    {"AnalysisComponent": {"AnalysisComponentIdentifier": 4, "AnalysisComponentType": "NewMatchPathValueDetector", "AnalysisComponentName": "AMiner: New status code in Apache Access log.", "Message": "New value(s) detected", "PersistenceFileName": "nmpvd_status_code", "TrainingMode": false, "AffectedLogAtomPaths": ["/model/status_code"], "AffectedLogAtomValues": ["403"]}, "LogData": {"RawLogData": ["172.21.128.119 - - [17/Jan/2022:11:22:02 +0000] \"GET /.htpasswd_ HTTP/1.1\" 403 366 \"-\" \"Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)\""], "Timestamps": [1642418522], "DetectionTimestamp": [1642418522], "LogLinesCount": 1, "LogResources": ["/var/log/apache2/intranet-access.log"]}, "AMiner": {"ID": "192.168.104.155"}}

    Output:
    {
        "anomaly_timestamp": "1642418522",
        "classification": "TP",
        "mitre_technique": ["Active Scanning: Wordlist Scanning"],
        "description": "The alert shows attempted access to a sensitive file (.htpasswd_) and therefore indicates probing. The _ indicates automated scanning because of the slightly changes spelling of a common file."
    }

    Example 6:
    ids_line:
    {"AnalysisComponent": {"AnalysisComponentIdentifier": 3, "AnalysisComponentType": "NewMatchPathDetector", "AnalysisComponentName": "AMiner: New event type.", "Message": "New path(es) detected", "PersistenceFileName": "nmpd", "TrainingMode": false, "AffectedLogAtomPaths": ["/model/with_data/fm/client/fm/ah", "/model/with_data/fm/client/fm/ah/ah_str", "/model/with_data/fm/client/fm/ah/ah_number", "/model/with_data/fm/client/fm/ah/colon", "/model/with_data/fm/client/fm/ah/msg"]}, "LogData": {"RawLogData": ["[Mon Jan 17 11:22:12.750845 2022] [negotiation:error] [pid 20391] [client 172.21.128.119:44584] AH00687: Negotiation: discovered file(s) matching request: /var/www/intranet.smith.santos.com/wp-login (None could be negotiated)."], "Timestamps": [1642418532.75], "DetectionTimestamp": [1642418532.75], "LogLinesCount": 1, "LogResources": ["/var/log/apache2/intranet-error.log"]}, "AMiner": {"ID": "192.168.104.155"}}

    Output:
    {
        "anomaly_timestamp": "1642418532.75",
        "classification": "TP",
        "mitre_technique": ["Active Scanning: Wordlist Scanning"],
        "description": "The request to /wp-login shows probing of a web login page that could be used for reconnaissance or direct exploitation attempts."
    }

    Example 7:
    ids_line:
    {"AnalysisComponent": {"AnalysisComponentIdentifier": 6, "AnalysisComponentType": "EntropyDetector", "AnalysisComponentName": "AMiner: High entropy in Apache Access request.", "Message": "Value entropy anomaly detected", "PersistenceFileName": "entropy_request", "TrainingMode": false, "AffectedLogAtomPaths": ["/model/fm/request/request"], "AffectedLogAtomValues": ["/wp-content/uploads/2022/01/yvmuplzucm-1642418578.1653.php?wp_meta=WyJteXNxbCIsICItdSIsICJ3b3JkcHJlc3MiLCAiLXB0YWlub294M2FlZGVlU2giLCAid29yZHByZXNzX2RiIiwgIi1lIiwgIlwic2VsZWN0ICogZnJvbSB3cF91c2Vyc1wiIl0%3D"], "CriticalValue": 0.038245009174066216, "ProbabilityThreshold": 0.05}, "LogData": {"RawLogData": ["172.21.128.119 - - [17/Jan/2022:11:24:14 +0000] \"GET /wp-content/uploads/2022/01/yvmuplzucm-1642418578.1653.php?wp_meta=WyJteXNxbCIsICItdSIsICJ3b3JkcHJlc3MiLCAiLXB0YWlub294M2FlZGVlU2giLCAid29yZHByZXNzX2RiIiwgIi1lIiwgIlwic2VsZWN0ICogZnJvbSB3cF91c2Vyc1wiIl0%3D HTTP/1.1\" 200 507755 \"-\" \"python-requests/2.27.1\""], "Timestamps": [1642418654], "DetectionTimestamp": [1642418654], "LogLinesCount": 1, "LogResources": ["/var/log/apache2/intranet-access.log"]}, "AMiner": {"ID": "192.168.104.155"}}

    Output:
    {
        "anomaly_timestamp": "1642418654",
        "classification": "TP",
        "mitre_technique": ["Server Software Component: Web Shell"],
        "description": "The high-entropy request is invoking a suspicious PHP file upload with encoded parameters, strongly indicating web shell interaction over HTTP."
    }

    Example 8:
    ids_line:
    {"AnalysisComponent": {"AnalysisComponentIdentifier": 11, "AnalysisComponentType": "EventCountClusterDetector", "AnalysisComponentName": "AMiner: Unusual occurrence frequencies of Apache Access request methods.", "Message": "Frequency anomaly detected", "PersistenceFileName": "eccd_request_method", "TrainingMode": false, "AffectedLogAtomPaths": ["/model/fm/request/method"], "AffectedLogAtomValues": [["1"], ["0"], ["6"], ["3"]], "AffectedLogAtomFrequencies": [102, 5408, 43, 3266], "AffectedIdValues": []}, "CountData": {"ConfidenceFactor": 0.5, "Confidence": 0.7504210171775009}, "LogData": {"RawLogData": ["172.21.128.119 - - [17/Jan/2022:11:24:14 +0000] \"GET /wp-content/uploads/2022/01/yvmuplzucm-1642418578.1653.php?wp_meta=WyJteXNxbCIsICItdSIsICJ3b3JkcHJlc3MiLCAiLXB0YWlub294M2FlZGVlU2giLCAid29yZHByZXNzX2RiIiwgIi1lIiwgIlwic2VsZWN0ICogZnJvbSB3cF91c2Vyc1wiIl0%3D HTTP/1.1\" 200 507755 \"-\" \"python-requests/2.27.1\""], "Timestamps": [1642418654], "DetectionTimestamp": [1642418654], "LogLinesCount": 1, "LogResources": ["/var/log/apache2/intranet-access.log"]}, "AMiner": {"ID": "192.168.104.155"}}

    Output:
    {
        "anomaly_timestamp": "1642418654",
        "classification": "TP",
        "mitre_technique": ["Server Software Component: Web Shell"],
        "description": "The unusual frequency of HTTP requests to a suspicious uploaded PHP file suggests repeated interaction with a web shell for e.g. command execution."
    }

    Example 9:
    ids_line:
    {"AnalysisComponent": {"AnalysisComponentIdentifier": 6, "AnalysisComponentType": "EntropyDetector", "AnalysisComponentName": "AMiner: High entropy in Apache Access request.", "Message": "Value entropy anomaly detected", "PersistenceFileName": "entropy_request", "TrainingMode": false, "AffectedLogAtomPaths": ["/model/fm/request/request"], "AffectedLogAtomValues": ["/wp-content/uploads/2022/01/yvmuplzucm-1642418578.1653.php?wp_meta=WyJ3Z2V0IiwgImh0dHBzOi8vZ2l0aHViLmNvbS9haXQtYWVjaWQvd3BoYXNoY3JhY2svYXJjaGl2ZS9yZWZzL3RhZ3MvdjAuMS50YXIuZ3oiXQ%3D%3D"], "CriticalValue": 0.04084936760975996, "ProbabilityThreshold": 0.05}, "LogData": {"RawLogData": ["172.21.128.119 - - [17/Jan/2022:11:24:16 +0000] \"GET /wp-content/uploads/2022/01/yvmuplzucm-1642418578.1653.php?wp_meta=WyJ3Z2V0IiwgImh0dHBzOi8vZ2l0aHViLmNvbS9haXQtYWVjaWQvd3BoYXNoY3JhY2svYXJjaGl2ZS9yZWZzL3RhZ3MvdjAuMS50YXIuZ3oiXQ%3D%3D HTTP/1.1\" 200 506723 \"-\" \"python-requests/2.27.1\""], "Timestamps": [1642418656], "DetectionTimestamp": [1642418656], "LogLinesCount": 1, "LogResources": ["/var/log/apache2/intranet-access.log"]}, "AMiner": {"ID": "192.168.104.155"}}

    Output:
    {
        "anomaly_timestamp": "1642418656",
        "classification": "TP",
        "mitre_technique": ["Server Software Component: Web Shell", "Brute Force: Password Cracking"],
        "description": "The high-entropy request to an uploaded PHP file (web shell) includes encoded parameters that trigger downloading and use of a password-cracking tool targeting WordPress credentials."
    }

    Example 10:
    ids_line:
    {"AnalysisComponent": {"AnalysisComponentIdentifier": 36, "AnalysisComponentType": "MatchValueAverageChangeDetector", "AnalysisComponentName": "AMiner: CPU value deviates from average in monitoring logs.", "Message": "Statistical data report", "PersistenceFileName": "Default", "TrainingMode": false, "AffectedLogAtomPaths": ["/model", "/model/metricset/version", "/model/agent/version", "/model/version", "/model/event/version", "/model/metricset/version/0", "/model/metricset/version/1", "/model/agent/version/0", "/model/agent/version/1", "/model/agent/version/2", "/model/agent/version/3", "/model/agent/version/4", "/model/version/0", "/model/host/cpu/version", "/model/host/version", "/model/version/1", "/model/system/cpu/val", "/model/system/cpu/steal/norm/version", "/model/system/cpu/steal/version", "/model/system/cpu/idle/norm/version", "/model/system/cpu/idle/version", "/model/system/cpu/iowait/norm/version", "/model/system/cpu/iowait/version", "/model/system/cpu/user/norm/version", "/model/system/cpu/user/version", "/model/system/cpu/nice/norm/val", "/model/system/cpu/nice/val", "/model/system/cpu/total/norm/val", "/model/system/cpu/total/val", "/model/system/cpu/irq/norm/version", "/model/system/cpu/irq/version", "/model/system/cpu/system/norm/val", "/model/system/cpu/system/val", "/model/system/cpu/softirq/norm/version", "/model/system/cpu/softirq/version", "/model/time", "/model/service/version", "/model/event/version/0", "/model/event/version/1", "/model/event/version/2", "/model/ecs/version"], "AnomalyScores": [{"Path": "/model/system/cpu/total/norm/val", "AnalysisData": {"New": {"N": 100, "Avg": 0.32027500000000014, "Var": 0.16587971967171702}, "Old": {"N": 3800, "Avg": 0.07500397368421052, "Var": 0.00110801380099957}}}], "MinBinElements": 100, "MinBinTime": 10, "DebugMode": false}, "LogData": {"RawLogData": ["{\"metricset\":{\"period\":45000,\"name\":\"cpu\"},\"agent\":{\"id\":\"ab5616c7-58c0-4480-a883-359041057b74\",\"hostname\":\"intranet-server\",\"type\":\"metricbeat\",\"ephemeral_id\":\"c1899c21-6022-4ee2-9f06-2248c8a823cf\",\"version\":\"7.13.2\",\"name\":\"intranet-server\"},\"tags\":[\"beats_input_raw_event\"],\"host\":{\"cpu\":{\"pct\":1},\"name\":\"intranet-server\"},\"@version\":\"1\",\"system\":{\"cpu\":{\"cores\":1,\"steal\":{\"norm\":{\"pct\":0},\"pct\":0},\"idle\":{\"norm\":{\"pct\":0},\"pct\":0},\"iowait\":{\"norm\":{\"pct\":0},\"pct\":0},\"user\":{\"norm\":{\"pct\":0.0185},\"pct\":0.0185},\"nice\":{\"norm\":{\"pct\":0.9591},\"pct\":0.9591},\"total\":{\"norm\":{\"pct\":1},\"pct\":1},\"irq\":{\"norm\":{\"pct\":0},\"pct\":0},\"system\":{\"norm\":{\"pct\":0.0222},\"pct\":0.0222},\"softirq\":{\"norm\":{\"pct\":2.0E-4},\"pct\":2.0E-4}}},\"@timestamp\":\"2022-01-17T11:44:28.504Z\",\"service\":{\"type\":\"system\"},\"event\":{\"duration\":586280,\"module\":\"system\",\"dataset\":\"system.cpu\"},\"ecs\":{\"version\":\"1.9.0\"}}"], "Timestamps": [1642419868.5], "DetectionTimestamp": [1642419868.5], "LogLinesCount": 1, "LogResources": ["/var/log/logstash/intranet-server/system.cpu.log"]}, "AMiner": {"ID": "192.168.104.214"}}

    Output:
    {
        "anomaly_timestamp": "1642419868.5",
        "classification": "TP",
        "mitre_technique": ["Brute Force"],
        "description": "The unusually high CPU usage is likely caused by password-cracking activity consistent with a brute-force attack"
    }

    Example 11:
    ids_line:
    {"AnalysisComponent": {"AnalysisComponentIdentifier": 6, "AnalysisComponentType": "EntropyDetector", "AnalysisComponentName": "AMiner: High entropy in Apache Access request.", "Message": "Value entropy anomaly detected", "PersistenceFileName": "entropy_request", "TrainingMode": false, "AffectedLogAtomPaths": ["/model/fm/request/request"], "AffectedLogAtomValues": ["/wp-content/uploads/2022/01/yvmuplzucm-1642418578.1653.php?wp_meta=WyJiYXNoIiwgIi1jIiwgIiAnMDwmMTk2O2V4ZWMgMTk2PD4vZGV2L3RjcC8xMC4yMjkuMi4yMTYvMTY0ODY7IHNoIDwmMTk2ID4mMTk2IDI%2BJjE5NiciLCAiJiJd"], "CriticalValue": 0.04595989988386346, "ProbabilityThreshold": 0.05}, "LogData": {"RawLogData": ["172.21.128.119 - - [17/Jan/2022:11:58:04 +0000] \"GET /wp-content/uploads/2022/01/yvmuplzucm-1642418578.1653.php?wp_meta=WyJiYXNoIiwgIi1jIiwgIiAnMDwmMTk2O2V4ZWMgMTk2PD4vZGV2L3RjcC8xMC4yMjkuMi4yMTYvMTY0ODY7IHNoIDwmMTk2ID4mMTk2IDI%2BJjE5NiciLCAiJiJd HTTP/1.1\" 200 506723 \"-\" \"python-requests/2.27.1\""], "Timestamps": [1642420684], "DetectionTimestamp": [1642420684], "LogLinesCount": 1, "LogResources": ["/var/log/apache2/intranet-access.log"]}, "AMiner": {"ID": "192.168.104.155"}}

    Output:
    {
        "anomaly_timestamp": "1642420684",
        "classification": "TP",
        "mitre_technique": ["Command and Scripting Interpreter: Unix Shell"],
        "description": "The alert shows an attacker exploiting a vulnerable PHP upload to deliver and execute a high-entropy bash reverse shell."
    }

    Example 12:
    ids_line:
    {"AnalysisComponent": {"AnalysisComponentIdentifier": 6, "AnalysisComponentType": "EntropyDetector", "AnalysisComponentName": "AMiner: High entropy in Apache Access request.", "Message": "Value entropy anomaly detected", "PersistenceFileName": "entropy_request", "TrainingMode": false, "AffectedLogAtomPaths": ["/model/fm/request/request"], "AffectedLogAtomValues": ["/wp-content/uploads/2022/01/zrhrldsngi-1643467181.254.php?wp_meta=WyJiYXNoIiwgIi1jIiwgIiAnMDwmMTk2O2V4ZWMgMTk2PD4vZGV2L3RjcC8xMC43MC4zMy4yMDIvNTU4MDE7IHNoIDwmMTk2ID4mMTk2IDI%2BJjE5NiciLCAiJiJd"], "CriticalValue": 0.04912596173510217, "ProbabilityThreshold": 0.05}, "LogData": {"RawLogData": ["172.24.249.224 - - [29/Jan/2022:15:20:39 +0000] \"GET /wp-content/uploads/2022/01/zrhrldsngi-1643467181.254.php?wp_meta=WyJiYXNoIiwgIi1jIiwgIiAnMDwmMTk2O2V4ZWMgMTk2PD4vZGV2L3RjcC8xMC43MC4zMy4yMDIvNTU4MDE7IHNoIDwmMTk2ID4mMTk2IDI%2BJjE5NiciLCAiJiJd HTTP/1.1\" 200 506735 \"-\" \"python-requests/2.27.1\""], "Timestamps": [1643469639], "DetectionTimestamp": [1643469639], "LogLinesCount": 1, "LogResources": ["/var/log/apache2/intranet-access.log"]}, "AMiner": {"ID": "192.168.188.179"}}

    Output:
    {
        "anomaly_timestamp": "1643469639",
        "classification": "TP",
        "mitre_technique": ["Command and Scripting Interpreter: Unix Shell"],
        "description": "The alert shows an high-entropy base64-encoded wp_meta parameter executing a bash reverse shell via a vulnerable PHP upload."
    }

    Example 13:
    ids_line:
    {"AnalysisComponent": {"AnalysisComponentIdentifier": 3, "AnalysisComponentType": "NewMatchPathDetector", "AnalysisComponentName": "AMiner: New event type.", "Message": "New path(es) detected", "PersistenceFileName": "nmpd", "TrainingMode": false, "AffectedLogAtomPaths": ["/model/service/su", "/model/service/su/systemd_str", "/model/service/su/id", "/model/service/su/brack_str2", "/model/service/su/fm/seq", "/model/service/su/fm/seq/brack_str", "/model/service/su/fm/seq/user", "/model/service/su/fm/seq/by_str", "/model/service/su/fm/seq/su_user"]}, "LogData": {"RawLogData": ["Jan 17 11:58:17 intranet-server su[20749]: Successful su for gmorgan by www-data"], "Timestamps": [1642420697], "DetectionTimestamp": [1642420697], "LogLinesCount": 1, "LogResources": ["/var/log/auth.log"]}, "AMiner": {"ID": "192.168.104.155"}}

    Output:
    {
        "anomaly_timestamp": "1642420697",
        "classification": "TP",
        "mitre_technique": ["Valid Accounts"],
        "description": "The alert shows the www-data process successfully using su to switch to the user gmorgan, indicating potential abuse of legitimate credentials for privilege escalation"
    }

    Example 14:
    ids_line:
    {"AnalysisComponent": {"AnalysisComponentIdentifier": 3, "AnalysisComponentType": "NewMatchPathDetector", "AnalysisComponentName": "AMiner: New event type.", "Message": "New path(es) detected", "PersistenceFileName": "nmpd", "TrainingMode": false, "AffectedLogAtomPaths": ["/model/service/sudo", "/model/service/sudo/cron_str", "/model/service/sudo/msg"]}, "LogData": {"RawLogData": ["Jan 17 11:58:29 intranet-server sudo:  gmorgan : TTY=pts/1 ; PWD=/var/www/intranet.smith.santos.com/wp-content/uploads/2022/01 ; USER=root ; COMMAND=/bin/cat /etc/shadow"], "Timestamps": [1642420709], "DetectionTimestamp": [1642420709], "LogLinesCount": 1, "LogResources": ["/var/log/auth.log"]}, "AMiner": {"ID": "192.168.104.155"}}

    Output:
    {
        "anomaly_timestamp": "1642420709",
        "classification": "TP",
        "mitre_technique": ["Valid Accounts"],
        "description": "The alert shows user gmorgan used sudo to execute /bin/cat /etc/shadow, indicating abuse of legitimate privileges to access sensitive data."
    }

    Example 15:
    ids_line:
    {"AnalysisComponent": {"AnalysisComponentIdentifier": 32, "AnalysisComponentType": "EventCountClusterDetector", "AnalysisComponentName": "AMiner: Unusual occurrence frequencies of DNS log events.", "Message": "Frequency anomaly detected", "PersistenceFileName": "eccd_dns", "TrainingMode": true, "AffectedLogAtomPaths": [], "AffectedLogAtomValues": [["/model", "/model/time", "/model/service", "/model/br_open", "/model/pid", "/model/br_close", "/model/type/query", "/model/type/query/query", "/model/type/query/record", "/model/type/query/br_close", "/model/type/query/domain", "/model/type/query/from", "/model/type/query/ip"], ["/model", "/model/time", "/model/service", "/model/br_open", "/model/pid", "/model/br_close", "/model/type/forwarded", "/model/type/forwarded/reply", "/model/type/forwarded/domain", "/model/type/forwarded/to", "/model/type/forwarded/ip"], ["/model", "/model/time", "/model/service", "/model/br_open", "/model/pid", "/model/br_close", "/model/type/nameserver", "/model/type/nameserver/nameserver", "/model/type/nameserver/ip", "/model/type/nameserver/refused"], ["/model", "/model/time", "/model/service", "/model/br_open", "/model/pid", "/model/br_close", "/model/type/reply", "/model/type/reply/reply", "/model/type/reply/domain", "/model/type/reply/is", "/model/type/reply/ip"]], "AffectedLogAtomFrequencies": [3, 3, 1, 5], "AffectedIdValues": []}, "CountData": {"ConfidenceFactor": 0.5, "Confidence": 0.9395604395604396}, "LogData": {"RawLogData": ["Jan 20 22:31:12 dnsmasq[14755]: query[A] intranet.hurstwong.wardbeck.info from 172.21.240.147"], "Timestamps": [1642717872], "DetectionTimestamp": [1642717872], "LogLinesCount": 1, "LogResources": ["/var/log/dnsmasq.log"]}, "AMiner": {"ID": "10.132.56.1"}}

    Output:
    {
        "anomaly_timestamp": "1642717872",
        "classification": "TP",
        "mitre_technique": ["Exfiltration Over C2 Channel"],
        "description": "The unusual DNS query frequencies indicate data is being covertly sent out of the network."
    }

    Example 16:
    ids_line:
    {"AnalysisComponent": {"AnalysisComponentIdentifier": 32, "AnalysisComponentType": "EventCountClusterDetector", "AnalysisComponentName": "AMiner: Unusual occurrence frequencies of DNS log events.", "Message": "Frequency anomaly detected", "PersistenceFileName": "eccd_dns", "TrainingMode": true, "AffectedLogAtomPaths": [], "AffectedLogAtomValues": [["/model", "/model/time", "/model/service", "/model/br_open", "/model/pid", "/model/br_close", "/model/type/query", "/model/type/query/query", "/model/type/query/record", "/model/type/query/br_close", "/model/type/query/domain", "/model/type/query/from", "/model/type/query/ip"], ["/model", "/model/time", "/model/service", "/model/br_open", "/model/pid", "/model/br_close", "/model/type/forwarded", "/model/type/forwarded/reply", "/model/type/forwarded/domain", "/model/type/forwarded/to", "/model/type/forwarded/ip"], ["/model", "/model/time", "/model/service", "/model/br_open", "/model/pid", "/model/br_close", "/model/type/nameserver", "/model/type/nameserver/nameserver", "/model/type/nameserver/ip", "/model/type/nameserver/refused"], ["/model", "/model/time", "/model/service", "/model/br_open", "/model/pid", "/model/br_close", "/model/type/reply", "/model/type/reply/reply", "/model/type/reply/domain", "/model/type/reply/is", "/model/type/reply/ip"], ["/model", "/model/time", "/model/service", "/model/br_open", "/model/pid", "/model/br_close", "/model/type/cached", "/model/type/cached/cached", "/model/type/cached/domain", "/model/type/cached/is", "/model/type/cached/ip"]], "AffectedLogAtomFrequencies": [8, 6, 2, 10, 2], "AffectedIdValues": []}, "CountData": {"ConfidenceFactor": 0.5, "Confidence": 0.5714285714285714}, "LogData": {"RawLogData": ["Jan 20 22:40:17 dnsmasq[14529]: query[TXT] current.cvd.clamav.net from 192.168.98.239"], "Timestamps": [1642718417], "DetectionTimestamp": [1642718417], "LogLinesCount": 1, "LogResources": ["/var/log/dnsmasq.log"]}, "AMiner": {"ID": "192.168.127.254"}}

    Output:
    {
        "anomaly_timestamp": "1642718417",
        "classification": "TP",
        "mitre_technique": ["Exfiltration Over C2 Channel"],
        "description": "The high-frequency DNS queries indicate potential covert data exfiltration over DNS."
    }

    Example 17:
    ids_line:
    {"AnalysisComponent": {"AnalysisComponentIdentifier": 34, "AnalysisComponentType": "EventCountClusterDetector", "AnalysisComponentName": "AMiner: Unusual occurrence frequencies of DNS query records.", "Message": "Frequency anomaly detected", "PersistenceFileName": "eccd_dns_record", "TrainingMode": true, "AffectedLogAtomPaths": ["/model/type/query/record"], "AffectedLogAtomValues": [["A"], ["SRV"], ["AAAA"], ["TXT"]], "AffectedLogAtomFrequencies": [262, 35, 31, 8], "AffectedIdValues": []}, "CountData": {"ConfidenceFactor": 0.3, "Confidence": 1}, "LogData": {"RawLogData": ["Jan 14 01:00:19 dnsmasq[14569]: query[A] 3x6-.633-.SM0QTCnaOLcx7xgL9vNFI0KXyPr/Xkc72Nd0DAz4/tbZQhFsb0v7/WA2o/4S-.Ro6LF8Lt02nJ4nyIZAM7dtmRjt3QOa/heoL/X/Kfhx7RDBgcmV53Dk4oYVMD-.8UV99PJ3z92*/9qeVTL5vSbvquEDtqRHxG48z8LBQ29x77qf5QPpT0szMM4N-.customers_2013.xlsx.kiirjekuimkpcrcioastvkeodpnimx.biz from 10.229.0.4"], "Timestamps": [1642122019], "DetectionTimestamp": [1642122019], "LogLinesCount": 1, "LogResources": ["/var/log/dnsmasq.log"]}, "AMiner": {"ID": "10.229.255.254"}}

    Output:
    {
        "anomaly_timestamp": "1642122019",
        "classification": "FP",
        "mitre_technique": [],
        "description": "The alert is likely a false positive because the training mode is still active, the detection confidence is low and no repeated suspicious behavior."
    }

    Example 18:
    ids_line:
    {"AnalysisComponent": {"AnalysisComponentIdentifier": 30, "AnalysisComponentType": "EntropyDetector", "AnalysisComponentName": "AMiner: High entropy in DNS domain.", "Message": "Value entropy anomaly detected", "PersistenceFileName": "entropy_dns_domain", "TrainingMode": true, "AffectedLogAtomPaths": ["/model/type/query/domain", "/model/type/reply/domain", "/model/type/forwarded/domain"], "AffectedLogAtomValues": ["hayes-mail"], "CriticalValue": 0.005412293925153259, "ProbabilityThreshold": 0.015}, "LogData": {"RawLogData": ["Jan 14 00:09:18 dnsmasq[14569]: query[AAAA] hayes-mail from 10.229.2.25"], "Timestamps": [1642118958], "DetectionTimestamp": [1642118958], "LogLinesCount": 1, "LogResources": ["/var/log/dnsmasq.log"]}, "AMiner": {"ID": "10.229.255.254"}}

    Output:
    {
        "anomaly_timestamp": "1642118958",
        "classification": "FP",
        "mitre_technique": [],
        "description": "The alert was triggered because the system is in training mode and encountered a domain it has not seen before."
    }
    """
elif dataset == "wazuh_two":
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

    ### Few-shot Examples:
    Example 1:
    ids_line:
    Input (IDS anomaly line):
    {"agent": {"ip": "10.229.0.4", "name": "wazuh-client", "id": "30"}, "manager": {"name": "wazuh.manager"}, "data": {"metadata": {"flowints": {"tls": {"anomaly": {"count": "2"}}}}, "tx_id": "0", "app_proto": "tls", "in_iface": "ens3", "src_ip": "54.173.41.153", "src_port": "443", "event_type": "alert", "alert": {"severity": "3", "signature_id": "2230003", "rev": "1", "gid": "1", "signature": "SURICATA TLS invalid handshake message", "action": "allowed", "category": "Generic Protocol Command Decode"}, "flow_id": "1319969355864039.000000", "dest_ip": "10.229.0.4", "proto": "TCP", "tls": {"version": "UNDETERMINED", "ja3": {"string": "771,4865-4867-4866-49195-49199-52393-52392-49196-49200-49162-49161-49171-49172-156-157-47-53-10,0-23-65281-10-11-16-5-51-43-13-28-21,29-23-24-25-256-257,0", "hash": "a75de44db3e351bbd8d38b64c41f444e"}, "sni": "ping.chartbeat.net"}, "dest_port": "58774", "flow": {"pkts_toserver": "7", "start": "2022-01-17T11:18:42.923623+0000", "bytes_toclient": "257", "bytes_toserver": "1830", "pkts_toclient": "3"}, "timestamp": "2022-01-17T11:18:43.274160+0000"}, "rule": {"firedtimes": 9, "mail": false, "level": 3, "description": "Suricata: Alert - SURICATA TLS invalid handshake message", "groups": ["ids", "suricata"], "id": "86601"}, "decoder": {"name": "json"}, "input": {"type": "log"}, "@timestamp": "2022-01-17T11:18:43.274160Z", "location": "/var/log/suricata/eve.json", "id": "1687475310.10001877"}

    Output:
    {
        "anomaly_timestamp": "2022-01-17T11:18:43.274160Z",
        "classification": "TP",
        "mitre_technique": ["Network Service Discovery", "Active Scanning: Vulnerability Scanning"],
        "description": "The alert reflects unusual TLS handshakes that could indicate reconnaissance activity probing services"
    }

    Example 2:
    ids_line:
    {"agent": {"ip": "10.229.0.4", "name": "wazuh-client", "id": "30"}, "manager": {"name": "wazuh.manager"}, "data": {"metadata": {"flowints": {"tls": {"anomaly": {"count": "4"}}}}, "tx_id": "0", "app_proto": "tls", "in_iface": "ens3", "src_ip": "10.229.0.4", "src_port": "59354", "event_type": "alert", "alert": {"severity": "3", "signature_id": "2230010", "rev": "1", "gid": "1", "signature": "SURICATA TLS invalid record/traffic", "action": "allowed", "category": "Generic Protocol Command Decode"}, "flow_id": "419518725118999.000000", "dest_ip": "185.54.150.79", "proto": "TCP", "tls": {"version": "UNDETERMINED", "ja3": {"string": "771,4865-4867-4866-49195-49199-52393-52392-49196-49200-49162-49161-49171-49172-156-157-47-53-10,0-23-65281-10-11-35-16-5-51-43-13-45-28-21,29-23-24-25-256-257,0", "hash": "aa7744226c695c0b2e440419848cf700"}, "sni": "geid.wbtrk.net"}, "dest_port": "443", "flow": {"pkts_toserver": "7", "start": "2022-01-17T11:18:46.089111+0000", "bytes_toclient": "1175", "bytes_toserver": "1526", "pkts_toclient": "6"}, "timestamp": "2022-01-17T11:18:46.160088+0000"}, "rule": {"firedtimes": 48, "mail": false, "level": 3, "description": "Suricata: Alert - SURICATA TLS invalid record/traffic", "groups": ["ids", "suricata"], "id": "86601"}, "decoder": {"name": "json"}, "input": {"type": "log"}, "@timestamp": "2022-01-17T11:18:46.160088Z", "location": "/var/log/suricata/eve.json", "id": "1687475313.10093926"}

    Output:
    {
        "anomaly_timestamp": "2022-01-17T11:18:46.160088Z",
        "classification": "TP",
        "mitre_technique": ["Network Service Discovery", "Active Scanning: Vulnerability Scanning"],
        "description": "The repeated invalid TLS records from the internal host to an external IP suggest reconnaissance or scanning activity"
    }

    Example 3:
    ids_line:
    {"agent": {"ip": "192.168.104.155", "name": "wazuh-client", "id": "26"}, "manager": {"name": "wazuh.manager"}, "data": {"protocol": "POST", "srcip": "172.21.128.119", "id": "404", "url": "/sdk"}, "rule": {"firedtimes": 9, "mail": false, "level": 5, "pci_dss": ["6.5", "11.4"], "tsc": ["CC6.6", "CC7.1", "CC8.1", "CC6.1", "CC6.8", "CC7.2", "CC7.3"], "description": "Web server 400 error code.", "groups": ["web", "accesslog", "attack"], "id": "31101", "nist_800_53": ["SA.11", "SI.4"], "gdpr": ["IV_35.7.d"]}, "decoder": {"name": "web-accesslog"}, "full_log": "172.21.128.119 - - [17/Jan/2022:11:21:46 +0000] \"POST /sdk HTTP/1.1\" 404 3269 \"-\" \"Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)\"", "input": {"type": "log"}, "@timestamp": "2022-01-17T11:21:46.000000Z", "location": "/var/log/apache2/intranet-access.log", "id": "1687475492.10116645"}

    Output:
    {
        "anomaly_timestamp": "2022-01-17T11:21:46.000000Z",
        "classification": "TP",
        "mitre_technique": ["Network Service Discovery", "Active Scanning: Vulnerability Scanning"],
        description": "The HTTP POST request resulting in a 404 from Nmap Scripting Engine indicates reconnaissance activity"
    }

    Example 4:
    ids_line:
    {"predecoder": {"hostname": "inet-dns", "program_name": "sshd", "timestamp": "Jan 17 11:21:32"}, "agent": {"ip": "10.229.255.254", "name": "wazuh-client", "id": "29"}, "manager": {"name": "wazuh.manager"}, "data": {"srcip": "10.229.2.216", "srcport": "44494"}, "rule": {"firedtimes": 2, "mail": false, "level": 6, "pci_dss": ["11.4"], "tsc": ["CC6.1", "CC6.8", "CC7.2", "CC7.3"], "description": "sshd: insecure connection attempt (scan).", "groups": ["syslog", "sshd", "recon"], "mitre": {"technique": ["SSH"], "id": ["T1021.004"], "tactic": ["Lateral Movement"]}, "id": "5706", "nist_800_53": ["SI.4"], "gdpr": ["IV_35.7.d"], "gpg13": ["4.12"]}, "decoder": {"parent": "sshd", "name": "sshd"}, "full_log": "Jan 17 11:21:32 inet-dns sshd[19201]: Did not receive identification string from 10.229.2.216 port 44494", "input": {"type": "log"}, "@timestamp": "2022-01-17T11:21:32.000000Z", "location": "/var/log/auth.log", "id": "1687475477.10106901"}

    Output:
    {
        "anomaly_timestamp": "2022-01-17T11:21:32.000000Z",
        "classification": "TP",
        "mitre_technique": ["Active Scanning", "Network Service Discovery"],
        "description": "The incomplete SSH handshake indicates active probing for available SSH services"
    }

    Example 5:
    ids_line:
    {"agent": {"ip": "192.168.104.155", "name": "wazuh-client", "id": "26"}, "manager": {"name": "wazuh.manager"}, "data": {"protocol": "HEAD", "srcip": "172.21.128.119", "id": "404", "url": "/wp-content/backup-db/"}, "rule": {"firedtimes": 4146, "mail": false, "level": 5, "pci_dss": ["6.5", "11.4"], "tsc": ["CC6.6", "CC7.1", "CC8.1", "CC6.1", "CC6.8", "CC7.2", "CC7.3"], "description": "Web server 400 error code.", "groups": ["web", "accesslog", "attack"], "id": "31101", "nist_800_53": ["SA.11", "SI.4"], "gdpr": ["IV_35.7.d"]}, "decoder": {"name": "web-accesslog"}, "full_log": "172.21.128.119 - - [17/Jan/2022:11:22:24 +0000] \"HEAD /wp-content/backup-db/ HTTP/1.1\" 404 146 \"https://intranet.smith.santos.com\" \"WPScan v3.8.20 (https://wpscan.com/wordpress-security-scanner)\"", "input": {"type": "log"}, "@timestamp": "2022-01-17T11:22:24.000000Z", "location": "/var/log/apache2/intranet-access.log", "id": "1687475530.13015899"}

    Output:
    {
        "anomaly_timestamp": "2022-01-17T11:22:24.000000Z",
        "classification": "TP",
        "mitre_technique": ["Active Scanning: Vulnerability Scanning"],
        "description": "The alert shows WPScan actively probing a WordPress site for exposed backup files which indicates active scanning as long as no pentesing is going on within the organisation."
    }

    Example 6:
    ids_line:
    {"agent": {"ip": "192.168.104.155", "name": "wazuh-client", "id": "26"}, "previous_output": "172.21.128.119 - - [17/Jan/2022:11:22:40 +0000] \"HEAD /wp-content/themes/TheStyle/timthumb.phpthumb.php HTTP/1.1\" 404 146 \"https://intranet.smith.santos.com\" \"WPScan v3.8.20 (https://wpscan.com/wordpress-security-scanner)\"\n172.21.128.119 - - [17/Jan/2022:11:22:40 +0000] \"HEAD /wp-content/themes/TheStyle/timthumb.phptimthumb.php HTTP/1.1\" 404 146 \"https://intranet.smith.santos.com\" \"WPScan v3.8.20 (https://wpscan.com/wordpress-security-scanner)\"\n172.21.128.119 - - [17/Jan/2022:11:22:40 +0000] \"HEAD /wp-content/themes/TheStyle/scripts/timthumb.php HTTP/1.1\" 404 146 \"https://intranet.smith.santos.com\" \"WPScan v3.8.20 (https://wpscan.com/wordpress-security-scanner)\"\n172.21.128.119 - - [17/Jan/2022:11:22:40 +0000] \"HEAD /wp-content/themes/TheStyle/thumb.php HTTP/1.1\" 404 146 \"https://intranet.smith.santos.com\" \"WPScan v3.8.20 (https://wpscan.com/wordpress-security-scanner)\"\n172.21.128.119 - - [17/Jan/2022:11:22:40 +0000] \"HEAD /wp-content/themes/TheStyle/timthumb.php HTTP/1.1\" 404 146 \"https://intranet.smith.santos.com\" \"WPScan v3.8.20 (https://wpscan.com/wordpress-security-scanner)\"\n172.21.128.119 - - [17/Jan/2022:11:22:40 +0000] \"HEAD /wp-content/themes/TheStyle/inc/timthumb.php HTTP/1.1\" 404 146 \"https://intranet.smith.santos.com\" \"WPScan v3.8.20 (https://wpscan.com/wordpress-security-scanner)\"\n172.21.128.119 - - [17/Jan/2022:11:22:40 +0000] \"HEAD /wp-content/themes/TheStyle/includes/timthumb.php HTTP/1.1\" 404 146 \"https://intranet.smith.santos.com\" \"WPScan v3.8.20 (https://wpscan.com/wordpress-security-scanner)\"\n172.21.128.119 - - [17/Jan/2022:11:22:40 +0000] \"HEAD /wp-content/themes/thestation/timthumb.php HTTP/1.1\" 404 146 \"https://intranet.smith.santos.com\" \"WPScan v3.8.20 (https://wpscan.com/wordpress-security-scanner)\"\n172.21.128.119 - - [17/Jan/2022:11:22:40 +0000] \"HEAD /wp-content/themes/thestation/tools/timthumb.php HTTP/1.1\" 404 146 \"https://intranet.smith.santos.com\" \"WPScan v3.8.20 (https://wpscan.com/wordpress-security-scanner)\"\n172.21.128.119 - - [17/Jan/2022:11:22:40 +0000] \"HEAD /wp-content/themes/TheStyle/cache/thimthumb.php HTTP/1.1\" 404 146 \"https://intranet.smith.santos.com\" \"WPScan v3.8.20 (https://wpscan.com/wordpress-security-scanner)\"\n172.21.128.119 - - [17/Jan/2022:11:22:40 +0000] \"HEAD /wp-content/themes/thestation/tools/timthumb.phpthumb.php HTTP/1.1\" 404 146 \"https://intranet.smith.santos.com\" \"WPScan v3.8.20 (https://wpscan.com/wordpress-security-scanner)\"", "manager": {"name": "wazuh.manager"}, "data": {"protocol": "HEAD", "srcip": "172.21.128.119", "id": "404", "url": "/wp-content/themes/the-theme/core/libs/thumbnails/thumb.php"}, "rule": {"firedtimes": 500, "mail": false, "level": 10, "pci_dss": ["6.5", "11.4"], "tsc": ["CC6.6", "CC7.1", "CC8.1", "CC6.1", "CC6.8", "CC7.2", "CC7.3"], "description": "Multiple web server 400 error codes from same source ip.", "groups": ["web", "accesslog", "web_scan", "recon"], "mitre": {"technique": ["Vulnerability Scanning"], "id": ["T1595.002"], "tactic": ["Reconnaissance"]}, "id": "31151", "nist_800_53": ["SA.11", "SI.4"], "frequency": 14, "gdpr": ["IV_35.7.d"]}, "decoder": {"name": "web-accesslog"}, "full_log": "172.21.128.119 - - [17/Jan/2022:11:22:40 +0000] \"HEAD /wp-content/themes/the-theme/core/libs/thumbnails/thumb.php HTTP/1.1\" 404 146 \"https://intranet.smith.santos.com\" \"WPScan v3.8.20 (https://wpscan.com/wordpress-security-scanner)\"", "input": {"type": "log"}, "@timestamp": "2022-01-17T11:22:40.000000Z", "location": "/var/log/apache2/intranet-access.log", "id": "1687475546.14990158"}

    Output:
    {
        "anomaly_timestamp": "2022-01-17T11:22:40.000000Z",
        "classification": "TP",
        "mitre_technique": ["Active Scanning: Vulnerability Scanning"],
        "description": "The alert shows repeatedly probing WordPress theme paths for vulnerable files which indicates scanning activity."
    }

    Example 7:
    ids_line:
    {"agent": {"ip": "192.168.104.155", "name": "wazuh-client", "id": "26"}, "manager": {"name": "wazuh.manager"}, "data": {"protocol": "GET", "srcip": "172.21.128.119", "id": "403", "url": "/.htpasswd_"}, "rule": {"firedtimes": 27, "mail": false, "level": 5, "pci_dss": ["6.5", "11.4"], "tsc": ["CC6.6", "CC7.1", "CC8.1", "CC6.1", "CC6.8", "CC7.2", "CC7.3"], "description": "Web server 400 error code.", "groups": ["web", "accesslog", "attack"], "id": "31101", "nist_800_53": ["SA.11", "SI.4"], "gdpr": ["IV_35.7.d"]}, "decoder": {"name": "web-accesslog"}, "full_log": "172.21.128.119 - - [17/Jan/2022:11:22:02 +0000] \"GET /.htpasswd_ HTTP/1.1\" 403 366 \"-\" \"Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)\"", "input": {"type": "log"}, "@timestamp": "2022-01-17T11:22:02.000000Z", "location": "/var/log/apache2/intranet-access.log", "id": "1687475508.10215310"}

    Output:
    {
        "anomaly_timestamp": "2022-01-17T11:22:02.000000Z",
        "classification": "TP",
        "mitre_technique": ["Active Scanning: Vulnerability Scanning"],
        "description": "There is a request attempting to access the sensitive .htpasswd file on a web server which indicates scanning."
    }

    Example 8:
    ids_line:
    {"agent": {"ip": "192.168.104.155", "name": "wazuh-client", "id": "26"}, "manager": {"name": "wazuh.manager"}, "data": {"protocol": "GET", "srcip": "172.21.128.119", "id": "404", "url": "/bash"}, "rule": {"firedtimes": 549, "mail": false, "level": 5, "pci_dss": ["6.5", "11.4"], "tsc": ["CC6.6", "CC7.1", "CC8.1", "CC6.1", "CC6.8", "CC7.2", "CC7.3"], "description": "Web server 400 error code.", "groups": ["web", "accesslog", "attack"], "id": "31101", "nist_800_53": ["SA.11", "SI.4"], "gdpr": ["IV_35.7.d"]}, "decoder": {"name": "web-accesslog"}, "full_log": "172.21.128.119 - - [17/Jan/2022:11:22:04 +0000] \"GET /bash HTTP/1.1\" 404 363 \"-\" \"Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)\"", "input": {"type": "log"}, "@timestamp": "2022-01-17T11:22:04.000000Z", "location": "/var/log/apache2/intranet-access.log", "id": "1687475510.10574229"}

    Output:
    {
        "anomaly_timestamp": "2022-01-17T11:22:04.000000Z",
        "classification": "TP",
        "mitre_technique": ["Active Scanning: Vulnerability Scanning"],
        "description": "The alert shows an access attempt for /bash which indicates probing for misconfigured or exposed shells."
    }

    Example 9:
    ids_line:
    {"agent": {"ip": "192.168.104.155", "name": "wazuh-client", "id": "26"}, "manager": {"name": "wazuh.manager"}, "data": {"metadata": {"flowints": {"http": {"anomaly": {"count": "1"}}}}, "tx_id": "1", "app_proto": "http", "in_iface": "ens3", "src_ip": "10.229.2.216", "src_port": "80", "event_type": "alert", "alert": {"severity": "3", "signature_id": "2221010", "rev": "1", "gid": "1", "signature": "SURICATA HTTP unable to match response to request", "action": "allowed", "category": "Generic Protocol Command Decode"}, "flow_id": "1814861280913956.000000", "dest_ip": "192.168.104.155", "proto": "TCP", "http": {"length": "363896", "http_port": "0", "url": "/libhtp::request_uri_not_seen"}, "dest_port": "44636", "flow": {"pkts_toserver": "38", "start": "2022-01-17T11:24:39.469540+0000", "bytes_toclient": "5996", "bytes_toserver": "2666", "pkts_toclient": "6"}, "timestamp": "2022-01-17T11:24:39.481507+0000"}, "rule": {"firedtimes": 90, "mail": false, "level": 3, "description": "Suricata: Alert - SURICATA HTTP unable to match response to request", "groups": ["ids", "suricata"], "id": "86601"}, "decoder": {"name": "json"}, "input": {"type": "log"}, "@timestamp": "2022-01-17T11:24:39.481507Z", "location": "/var/log/suricata/eve.json", "id": "1687475666.15573167"}

    Output:
    {
        "anomaly_timestamp": "2022-01-17T11:24:39.481507Z",
        "classification": "TP",
        "mitre_technique": ["Brute Force: Password Guessing"],
        "description": "The alert shows HTTP traffic anomalies which might be generated because of repeated password attempts."
    }

    Example 10:
    ids_line:
    {"agent": {"ip": "10.229.0.4", "name": "wazuh-client", "id": "30"}, "manager": {"name": "wazuh.manager"}, "data": {"metadata": {"flowints": {"http": {"anomaly": {"count": "1"}}}}, "tx_id": "1", "app_proto": "http", "in_iface": "ens3", "src_ip": "10.229.2.216", "src_port": "80", "event_type": "alert", "alert": {"severity": "3", "signature_id": "2221010", "rev": "1", "gid": "1", "signature": "SURICATA HTTP unable to match response to request", "action": "allowed", "category": "Generic Protocol Command Decode"}, "flow_id": "2203938073291969.000000", "dest_ip": "10.229.0.4", "proto": "TCP", "http": {"length": "363896", "http_port": "0", "url": "/libhtp::request_uri_not_seen"}, "dest_port": "44636", "flow": {"pkts_toserver": "37", "start": "2022-01-17T11:24:39.470209+0000", "bytes_toclient": "5996", "bytes_toserver": "2600", "pkts_toclient": "6"}, "timestamp": "2022-01-17T11:24:39.481555+0000"}, "rule": {"firedtimes": 88, "mail": false, "level": 3, "description": "Suricata: Alert - SURICATA HTTP unable to match response to request", "groups": ["ids", "suricata"], "id": "86601"}, "decoder": {"name": "json"}, "input": {"type": "log"}, "@timestamp": "2022-01-17T11:24:39.481555Z", "location": "/var/log/suricata/eve.json", "id": "1687475666.15569078"}

    Output:
    {
        "anomaly_timestamp": "2022-01-17T11:24:39.481555Z",
        "classification": "TP",
        "mitre_technique": ["Brute Force: Password Guessing"],
        "description": "The log shows HTTP anomalies generated during repeated authentication attempts."
    }

    Example 11:
    ids_line:
    {"predecoder": {"hostname": "intranet-server", "program_name": "su", "timestamp": "Jan 17 11:58:17"}, "agent": {"ip": "192.168.104.155", "name": "wazuh-client", "id": "26"}, "manager": {"name": "wazuh.manager"}, "data": {"srcuser": "www", "dstuser": "data:gmorgan"}, "rule": {"mail": false, "level": 3, "pci_dss": ["10.2.5"], "hipaa": ["164.312.b"], "tsc": ["CC6.8", "CC7.2", "CC7.3"], "description": "User successfully changed UID.", "groups": ["syslog", "su", "authentication_success"], "nist_800_53": ["AU.14", "AC.7"], "gdpr": ["IV_35.7.d", "IV_32.2"], "firedtimes": 1, "mitre": {"technique": ["Valid Accounts"], "id": ["T1078"], "tactic": ["Defense Evasion", "Persistence", "Privilege Escalation", "Initial Access"]}, "id": "5304", "gpg13": ["7.6", "7.8"]}, "decoder": {"parent": "su", "name": "su"}, "full_log": "Jan 17 11:58:17 intranet-server su[20749]: + /dev/pts/1 www-data:gmorgan", "input": {"type": "log"}, "@timestamp": "2022-01-17T11:58:17.000000Z", "location": "/var/log/auth.log", "id": "1687477683.16223775"}

    Output:
    {
        "anomaly_timestamp": "2022-01-17T11:58:17.000000Z",
        "classification": "TP",
        "mitre_technique": ["Valid Accounts"],
        "description": "The alert shows a successful user switch (su) demonstrating use of legitimate credentials to escalate privileges."
    }

    Example 12:
    ids_line:
    {"predecoder": {"hostname": "intranet-server", "program_name": "sudo", "timestamp": "Jan 17 11:58:29"}, "agent": {"ip": "192.168.104.155", "name": "wazuh-client", "id": "26"}, "manager": {"name": "wazuh.manager"}, "data": {"srcuser": "gmorgan", "dstuser": "root", "tty": "pts/1", "pwd": "/var/www/intranet.smith.santos.com/wp-content/uploads/2022/01", "command": "/bin/cat /etc/shadow"}, "rule": {"mail": false, "level": 3, "pci_dss": ["10.2.5", "10.2.2"], "hipaa": ["164.312.b"], "tsc": ["CC6.8", "CC7.2", "CC7.3"], "description": "Successful sudo to ROOT executed.", "groups": ["syslog", "sudo"], "nist_800_53": ["AU.14", "AC.7", "AC.6"], "gdpr": ["IV_32.2"], "firedtimes": 1, "mitre": {"technique": ["Sudo and Sudo Caching"], "id": ["T1548.003"], "tactic": ["Privilege Escalation", "Defense Evasion"]}, "id": "5402", "gpg13": ["7.6", "7.8", "7.13"]}, "decoder": {"parent": "sudo", "name": "sudo", "ftscomment": "First time user executed the sudo command"}, "full_log": "Jan 17 11:58:29 intranet-server sudo:  gmorgan : TTY=pts/1 ; PWD=/var/www/intranet.smith.santos.com/wp-content/uploads/2022/01 ; USER=root ; COMMAND=/bin/cat /etc/shadow", "input": {"type": "log"}, "@timestamp": "2022-01-17T11:58:29.000000Z", "location": "/var/log/auth.log", "id": "1687477695.16225611"}

    Output:
    {
        "anomaly_timestamp": "2022-01-17T11:58:29.000000Z",
        "classification": "TP",
        "mitre_technique": ["Abuse Elevation Control Mechanism: Sudo and Sudo Caching"],
        "description": "The alert indicates the technique Sudo and Sudo Caching because the user gmorgan successfully executed a sudo command to access root and read /etc/shadow demonstrating privilege escalation."
    }

    Example 13:
    ids_line:
    {"agent": {"ip": "10.132.56.1", "name": "wazuh-client", "id": "30"}, "manager": {"name": "wazuh.manager"}, "data": {"metadata": {"flowints": {"tls": {"anomaly": {"count": "2"}}}}, "tx_id": "0", "app_proto": "tls", "in_iface": "ens3", "src_ip": "34.213.76.57", "src_port": "443", "event_type": "alert", "alert": {"severity": "3", "signature_id": "2230003", "rev": "1", "gid": "1", "signature": "SURICATA TLS invalid handshake message", "action": "allowed", "category": "Generic Protocol Command Decode"}, "flow_id": "1981255141899576.000000", "dest_ip": "192.168.96.4", "proto": "TCP", "tls": {"version": "UNDETERMINED", "ja3": {"string": "771,4865-4867-4866-49195-49199-52393-52392-49196-49200-49162-49161-49171-49172-156-157-47-53-10,0-23-65281-10-11-35-16-5-51-43-13-45-28-21,29-23-24-25-256-257,0", "hash": "aa7744226c695c0b2e440419848cf700"}, "sni": "shavar.services.mozilla.com"}, "dest_port": "39008", "flow": {"pkts_toserver": "6", "start": "2022-01-20T22:57:53.539960+0000", "bytes_toclient": "257", "bytes_toserver": "2198", "pkts_toclient": "3"}, "timestamp": "2022-01-20T22:57:54.110943+0000"}, "rule": {"firedtimes": 1, "mail": false, "level": 3, "description": "Suricata: Alert - SURICATA TLS invalid handshake message", "groups": ["ids", "suricata"], "id": "86601"}, "decoder": {"name": "json"}, "input": {"type": "log"}, "@timestamp": "2022-01-20T22:57:54.110943Z", "location": "/var/log/suricata/eve.json", "id": "1688540918.2845670"}

    Output:
    {
        "anomaly_timestamp": "2022-01-20T22:57:54.110943Z",
        "classification": "TP",
        "mitre_technique": ["Exfiltration Over C2 Channel"],
        "description": "The alert indicates exfiltration over C2 channel because the detected invalid TLS handshake likely represents DNS tunneling data over TLS to exfiltrate sensitive information."
    }

    Example 14:
    ids_line:
    {"agent": {"ip": "10.132.56.1", "name": "wazuh-client", "id": "30"}, "manager": {"name": "wazuh.manager"}, "data": {"metadata": {"flowints": {"tls": {"anomaly": {"count": "2"}}}}, "tx_id": "0", "app_proto": "tls", "in_iface": "ens3", "src_ip": "34.213.76.57", "src_port": "443", "event_type": "alert", "alert": {"severity": "3", "signature_id": "2230010", "rev": "1", "gid": "1", "signature": "SURICATA TLS invalid record/traffic", "action": "allowed", "category": "Generic Protocol Command Decode"}, "flow_id": "1981255141899576.000000", "dest_ip": "192.168.96.4", "proto": "TCP", "tls": {"version": "UNDETERMINED", "ja3": {"string": "771,4865-4867-4866-49195-49199-52393-52392-49196-49200-49162-49161-49171-49172-156-157-47-53-10,0-23-65281-10-11-35-16-5-51-43-13-45-28-21,29-23-24-25-256-257,0", "hash": "aa7744226c695c0b2e440419848cf700"}, "sni": "shavar.services.mozilla.com"}, "dest_port": "39008", "flow": {"pkts_toserver": "6", "start": "2022-01-20T22:57:53.539960+0000", "bytes_toclient": "257", "bytes_toserver": "2198", "pkts_toclient": "3"}, "timestamp": "2022-01-20T22:57:54.110943+0000"}, "rule": {"firedtimes": 2, "mail": false, "level": 3, "description": "Suricata: Alert - SURICATA TLS invalid record/traffic", "groups": ["ids", "suricata"], "id": "86601"}, "decoder": {"name": "json"}, "input": {"type": "log"}, "@timestamp": "2022-01-20T22:57:54.110943Z", "location": "/var/log/suricata/eve.json", "id": "1688540918.2847671"}

    Output:
    {
        "anomaly_timestamp": "2022-01-20T22:57:54.110943Z",
        "classification": "TP",
        "mitre_technique": ["Exfiltration Over C2 Channel"],
        "description": "The alert shows anomalous TLS traffic from an external IP to an internal host consistent with DNS-based or encrypted channels."
    }

    Example 15:
    ids_line:
    {"predecoder": {"hostname": "mail", "program_name": "dovecot", "timestamp": "Jan 14 05:24:34"}, "agent": {"ip": "172.21.131.50", "name": "wazuh-client", "id": "22"}, "manager": {"name": "wazuh.manager"}, "rule": {"mail": false, "level": 3, "pci_dss": ["10.2.5"], "hipaa": ["164.312.b"], "tsc": ["CC6.8", "CC7.2", "CC7.3"], "description": "Dovecot Authentication Success.", "groups": ["dovecot", "authentication_success"], "nist_800_53": ["AU.14", "AC.7"], "gdpr": ["IV_32.2"], "firedtimes": 1, "mitre": {"technique": ["Valid Accounts"], "id": ["T1078"], "tactic": ["Defense Evasion", "Persistence", "Privilege Escalation", "Initial Access"]}, "id": "9701", "gpg13": ["7.1", "7.2"]}, "decoder": {"parent": "dovecot", "name": "dovecot"}, "full_log": "Jan 14 05:24:34 mail dovecot: imap-login: Login: user=<danny.jarvis>, method=PLAIN, rip=172.21.131.50, lip=172.21.131.50, mpid=7889, TLS, session=<RvV0BITVsNqsFYMy>", "input": {"type": "log"}, "@timestamp": "2022-01-14T05:24:34.000000Z", "location": "/var/log/mail.info", "id": "1687194860.7620703"}

    Output:
    {
        "anomaly_timestamp": "2022-01-14T05:24:34.000000Z",
        "classification": "FP",
        "mitre_technique": [],
        "description": "This alert is a false positive because it's a normal, successful login by a legitimate internal user over TLS"
    }

    Example 16:
    ids_line:
    {"predecoder": {"hostname": "hayes-mail", "program_name": "freshclam", "timestamp": "Jan 17 10:25:16"}, "agent": {"ip": "10.229.2.25", "name": "wazuh-client", "id": "21"}, "manager": {"name": "wazuh.manager"}, "rule": {"firedtimes": 1, "mail": false, "level": 3, "pci_dss": ["5.2"], "tsc": ["A1.2"], "description": "ClamAV database update", "groups": ["clamd", "freshclam", "virus"], "id": "52507", "nist_800_53": ["SI.3"], "gpg13": ["4.4"], "gdpr": ["IV_35.7.d"]}, "decoder": {"name": "freshclam"}, "full_log": "Jan 17 10:25:16 hayes-mail freshclam[28734]: Mon Jan 17 10:25:16 2022 -> ClamAV update process started at Mon Jan 17 10:25:16 2022", "input": {"type": "log"}, "@timestamp": "2022-01-17T10:25:16.000000Z", "location": "/var/log/syslog", "id": "1687472101.8942636"}

    Output:
    {
        "anomaly_timestamp": "2022-01-17T10:25:16.000000Z",
        "classification": "FP",
        "mitre_technique": [],
        "description": "This alert is a false positive because it simply logs a routine ClamAV virus database update"
    }
    """

with open("../llm_keys/openai.txt", "r") as file:
    os.environ["OPENAI_API_KEY"] = file.read().strip()

client = OpenAI()

processed_lines = []

class Classification(BaseModel):
    anomaly_timestamp: str
    classification: str
    mitre_technique: list[str]
    description: str

timestamp = datetime.now().strftime('%d_%m_%Y_%H_%M')
filename = "./" + input_file_name[:-5].replace("../test_data/LLM/", "../preprocessing_files/zero_shot/consistency/chatgpt/") + "_" + timestamp + "_results.json"

with open(input_file_name, "r") as input_lines:
    for i, line in enumerate(input_lines, start=1):

        client = OpenAI()

        response = client.responses.parse(
            model="gpt-4o-2024-08-06",
            temperature=0.0,
            top_p=1.0,
            max_output_tokens=1000,
            text_format=Classification,
            input=[
                {"role": "system", "content": system_message},
                {"role": "user", "content": f"Now classify the following IDS line:\n\nids_line:\n{json.dumps(line)}"}
            ]
        )

        processed_lines.append({
            "line_number": i,
            "input": line,
            "output": response.output_parsed.model_dump()
        })

        with open(filename, "w") as f:
            json.dump(processed_lines, f, indent=2)
        print("Line number " + str(i) + " processed.")
        time.sleep(2) # Tier 1: use 20 seconds for one_shot and 30 seconds for two_shot to stay within rate limits

print(f"{len(processed_lines)} lines processed from {input_file_name}")

with open(filename, "w") as f:
    json.dump(processed_lines, f, indent=2)

print("Results saved to" + filename)
