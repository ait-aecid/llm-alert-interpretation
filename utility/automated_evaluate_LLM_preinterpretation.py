import json
import argparse

def validate_classifications(techniques, attack_type, mapping, predicted_techniques):

    if len(predicted_techniques) == 0:
        return "" 

    technique_lookup = {tech['name']: tech['id'] for tech in techniques}

    if attack_type not in mapping:
        return "No classification expected as the alert is a false positive."
    
    result = ""
    mitre_ids = []
    count_non_existent_techniques = 0 # the provided technique is not a valid mitre technique
    count_expected_techniques = 0 # the technique is a valid mitre technique and within the list of expected techniques
    count_incorrect_techniques = 0 # not within the list of expected techniques

    for technique in predicted_techniques:
        if any(item["id"] == technique for item in techniques):
            mitre_ids.append(technique)
        elif technique in technique_lookup:
            mitre_ids.append(technique_lookup[technique])
        else:
            count_non_existent_techniques += 1
            result += f"Technique {technique} does not exist;"

    possible_mitre_ids = mapping[attack_type]

    for id in mitre_ids:
        if id in possible_mitre_ids:
            count_expected_techniques += 1
        else:
            count_incorrect_techniques += 1
            result += f"Incorrect id: {id};"
        
    if count_expected_techniques == len(predicted_techniques):
        return "Correct classification - All provided techniques are correct"
    elif count_expected_techniques > 0:
        return "Partially correct classification - " + result
    else:
        return "Incorrect classification - " + result
    
def correct_attack_types(correct_lines, partically_correct_lines, incorrect_lines, attack_types_lines):
    result = ""

    dnsteal_count = (0,0,0)
    network_scan_count = (0,0,0)
    service_scan_count = (0,0,0)
    wpscan_count = (0,0,0)
    dirb_count = (0,0,0)
    webshell_count = (0,0,0)
    password_cracking_count = (0,0,0)
    privilege_escalation_count = (0,0,0)
    reverse_shell_count = (0,0,0)

    # correctly classified
    for line in correct_lines:
        attack_type = attack_types_lines[line["line_number"]-1]
        
        match attack_type:
            case "dnsteal":
                dnsteal_count = (dnsteal_count[0] + 1, dnsteal_count[1], dnsteal_count[2])
            case "networkscans":
                network_scan_count = (network_scan_count[0] + 1, network_scan_count[1], network_scan_count[2])
            case "servicescans":
                service_scan_count = (service_scan_count[0] + 1, service_scan_count[1], service_scan_count[2])
            case "wpscan":
                wpscan_count = (wpscan_count[0] + 1, wpscan_count[1], wpscan_count[2])
            case "dirb":
                dirb_count = (dirb_count[0] + 1, dirb_count[1], dirb_count[2])
            case "webshell":
                webshell_count = (webshell_count[0] + 1, webshell_count[1], webshell_count[2])
            case "passwordcracking":
                password_cracking_count = (password_cracking_count[0] + 1, password_cracking_count[1], password_cracking_count[2])
            case "privilegeescalation":
                privilege_escalation_count = (privilege_escalation_count[0] + 1, privilege_escalation_count[1], privilege_escalation_count[2])
            case "reverseshell":
                reverse_shell_count = (reverse_shell_count[0] + 1, reverse_shell_count[1], reverse_shell_count[2])

    # partially correctly classified
    for line in partically_correct_lines:
        attack_type = attack_types_lines[line["line_number"]-1]
        match attack_type:
            case "dnsteal":
                dnsteal_count = (dnsteal_count[0], dnsteal_count[1] + 1, dnsteal_count[2])
            case "networkscans":
                network_scan_count = (network_scan_count[0], network_scan_count[1] + 1, network_scan_count[2])
            case "servicescans":
                service_scan_count = (service_scan_count[0], service_scan_count[1] + 1, service_scan_count[2])
            case "wpscan":
                wpscan_count = (wpscan_count[0], wpscan_count[1] + 1, wpscan_count[2])
            case "dirb":
                dirb_count = (dirb_count[0], dirb_count[1] + 1, dirb_count[2])
            case "webshell":
                webshell_count = (webshell_count[0], webshell_count[1] + 1, webshell_count[2])
            case "passwordcracking":
                password_cracking_count = (password_cracking_count[0], password_cracking_count[1] + 1, password_cracking_count[2])
            case "privilegeescalation":
                privilege_escalation_count = (privilege_escalation_count[0], privilege_escalation_count[1] + 1, privilege_escalation_count[2])
            case "reverseshell":
                reverse_shell_count = (reverse_shell_count[0], reverse_shell_count[1] + 1, reverse_shell_count[2])

    # incorrectly classified
    for line in incorrect_lines:
        attack_type = attack_types_lines[line["line_number"]-1]
        match attack_type:
            case "dnsteal":
                dnsteal_count = (dnsteal_count[0], dnsteal_count[1], dnsteal_count[2] + 1)
            case "networkscans":
                network_scan_count = (network_scan_count[0], network_scan_count[1], network_scan_count[2] + 1)
            case "servicescans":
                service_scan_count = (service_scan_count[0], service_scan_count[1], service_scan_count[2] + 1)
            case "wpscan":
                wpscan_count = (wpscan_count[0], wpscan_count[1], wpscan_count[2] + 1)
            case "dirb":
                dirb_count = (dirb_count[0], dirb_count[1], dirb_count[2] + 1)
            case "webshell":
                webshell_count = (webshell_count[0], webshell_count[1], webshell_count[2] + 1)
            case "passwordcracking":
                password_cracking_count = (password_cracking_count[0], password_cracking_count[1], password_cracking_count[2] + 1)
            case "privilegeescalation":
                privilege_escalation_count = (privilege_escalation_count[0], privilege_escalation_count[1], privilege_escalation_count[2] + 1)
            case "reverseshell":
                reverse_shell_count = (reverse_shell_count[0], reverse_shell_count[1], reverse_shell_count[2] + 1)

    result = "Correctly classified per attack type: \n" \
    "DNSteal: C - " + str(dnsteal_count[0]) + ", PC: " + str(dnsteal_count[1]) + ", IC: " + str(dnsteal_count[2]) + "\n" \
    "Network Scans: C - " + str(network_scan_count[0]) + ", PC: " + str(network_scan_count[1]) + ", IC: " + str(network_scan_count[2]) + "\n" \
    "Service Scans: C - " + str(service_scan_count[0]) + ", PC: " + str(service_scan_count[1]) + ", IC: " + str(service_scan_count[2]) + "\n" \
    "WPScan: C - " + str(wpscan_count[0]) + ", PC: " + str(wpscan_count[1]) + ", IC: " + str(wpscan_count[2]) + "\n" \
    "Dirb: C - " + str(dirb_count[0]) + ", PC: " + str(dirb_count[1]) + ", IC: " + str(dirb_count[2]) + "\n" \
    "Web Shell: C - " + str(webshell_count[0]) + ", PC: " + str(webshell_count[1]) + ", IC: " + str(webshell_count[2]) + "\n" \
    "Password Cracking: C - " + str(password_cracking_count[0]) + ", PC: " + str(password_cracking_count[1]) + ", IC: " + str(password_cracking_count[2]) + "\n" \
    "Privilege Escalation: C - " + str(privilege_escalation_count[0]) + ", PC: " + str(privilege_escalation_count[1]) + ", IC: " + str(privilege_escalation_count[2]) + "\n" \
    "Reverse Shell: C - " + str(reverse_shell_count[0]) + ", PC: " + str(reverse_shell_count[1]) + ", IC: " + str(reverse_shell_count[2]) + "\n" \

    return result

def false_negatives_attack_types(correct_lines, attack_types_lines):
    result = ""

    dnsteal_count = 0
    network_scan_count = 0
    service_scan_count = 0
    wpscan_count = 0
    dirb_count = 0
    webshell_count = 0
    password_cracking_count = 0
    privilege_escalation_count = 0
    reverse_shell_count = 0

    # correctly classified
    for line in correct_lines:
        attack_type = attack_types_lines[line["line_number"]-1]
        
        match attack_type:
            case "dnsteal":
                dnsteal_count += 1
            case "networkscans":
                network_scan_count += 1
            case "servicescans":
                service_scan_count += 1
            case "wpscan":
                wpscan_count += 1
            case "dirb":
                dirb_count += 1
            case "webshell":
                webshell_count += 1
            case "passwordcracking":
                password_cracking_count += 1
            case "privilegeescalation":
                privilege_escalation_count += 1
            case "reverseshell":
                reverse_shell_count += 1

    result = "False negatives per attack type: \n" \
    "DNSteal: " + str(dnsteal_count) + "\n" \
    "Network Scans: " + str(network_scan_count) + "\n" \
    "Service Scans: " + str(service_scan_count) + "\n" \
    "WPScan: " + str(wpscan_count) + "\n" \
    "Dirb: " + str(dirb_count) + "\n" \
    "Web Shell: " + str(webshell_count) + "\n" \
    "Password Cracking: " + str(password_cracking_count) + "\n" \
    "Privilege Escalation: " + str(privilege_escalation_count) + "\n" \
    "Reverse Shell: " + str(reverse_shell_count) + "\n" 

    return result

if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='Validate classifications in a JSON file against a mapping and a technique file.',
        formatter_class=argparse.RawTextHelpFormatter
    )
    
    parser.add_argument('--technique_file', type=str, required=True, help='Path to the JSON file containing technique IDs and names.')
    parser.add_argument('--classification_file', type=str, required=True, help='Path to the JSON file containing classifications, IDs, and attack types.')
    parser.add_argument('--test_data_file', type=str, required=True, help='Path to the JSON file containing initial input data.')
    parser.add_argument('--mapping_file', type=str, required=True, help='Path to the JSON file containing mappings from attack types to allowed names.')
    parser.add_argument('--llm_type', type=str, required=True)
    parser.add_argument('--attacks', type=str, required=True)
    parser.add_argument('--run', type=str, required=True)
    parser.add_argument("--output", type=str, required=True)
    
    args = parser.parse_args()
    llm = args.llm_type
    classification_file = args.classification_file
    test_data_file = args.test_data_file
    technique_file = args.technique_file
    mapping_file = args.mapping_file
    attacks = args.attacks == "y"
    run = args.run
    output_path = args.output
    
    with open(args.technique_file, "r") as f:
        techniques = json.load(f)

    with open(args.mapping_file, "r") as f:
        mappings = json.load(f)

    original_lines = ""
    line_description = []
    
    name = test_data_file.split(".")[0]
    attack_types_lines = []

    if(attacks):
        with open('./test_data/LLM/' + name + '_lines.txt', 'r') as file:
            line_description = file.readlines()
            new_description = []
            attack_types = []
            for line in line_description:
                line = line.replace(",", "").split()
                attack_type = line[-1:]
                description = line[:-2]
                
                if(len(attack_type) == 0):
                    break
                attack_types.append(attack_type[0])
                new_description.append(description)
            
            for i in range(0, len(new_description)):
                for line in new_description[i]:
                    attack_types_lines.append(attack_types[i].lower())
    else:
        attack_types_lines = ["" for x in range(100)]

    countTP = 0
    TP_list = []
    countFN = 0
    FN_list=[]
    countTN = 0
    TN_list = []
    countFP = 0
    FP_list = []

    correct_classification = 0
    partially_correct_classification = 0
    incorrect_classification = 0
    no_request = 0

    correctly_classified = []
    partially_correctly_classified = []
    incorrectly_classified = []

    with open(classification_file, 'r') as processed:
        processed_lines = json.load(processed)

        for i in range(0, len(processed_lines)):

            if isinstance(processed_lines[i]["output"], str) and processed_lines[i]["output"].startswith("No request was sent"):
                validation_result = "No request sent."
            else:
                if processed_lines[i]["output"]["classification"] == "FP":
                    predicted_attack_type = ""
                else:
                    predicted_attack_type = processed_lines[i]["output"]["mitre_technique"]
                validation_result = validate_classifications(techniques, attack_types_lines[i], mappings, predicted_attack_type)

            if validation_result == "No request sent.":
                no_request += 1
            elif validation_result.startswith("Correct classification"):
                correct_classification += 1
                correctly_classified.append(processed_lines[i])
            elif validation_result.startswith("Partially correct classification"):
                partially_correct_classification += 1
                partially_correctly_classified.append(processed_lines[i])
            elif attacks and processed_lines[i]["output"]["classification"] == "TP":
                incorrect_classification += 1
                incorrectly_classified.append(processed_lines[i])           

            if not (validation_result == "No request sent."):
                output = {
                        "line_number": processed_lines[i]["line_number"],
                        "predicted_attack_type": predicted_attack_type,
                        "attack_type": attack_types_lines[i],
                        "classification_correct": validation_result,
                        "classification": processed_lines[i]["output"]["classification"],
                        "description": processed_lines[i]["output"]["description"],
                        "anomaly": processed_lines[i]["input"]
                    }
            
            if isinstance(processed_lines[i]["output"], str):
                continue
            if attacks:
                if processed_lines[i]["output"]["classification"] == "TP":
                    countTP += 1
                    TP_list.append(output)
                else: 
                    countFN += 1
                    FN_list.append(output)
            else:
                if processed_lines[i]["output"]["classification"] == "TP":
                    countFP += 1
                    FP_list.append(output)
                else: 
                    countTN += 1
                    TN_list.append(output)

    output_file = f"{output_path}/{run}_run/"

    result_overview = ""

    class_file = classification_file.split("/")[-1]
    if args.attacks == "y":
        with open(output_file + '/TP_list_' + llm +  "_" + class_file, "w") as output:  
            json.dump(TP_list, output, indent=2)
        
        with open(output_file + '/FN_list_' + llm +  "_" + class_file, "w") as output: 
            json.dump(FN_list, output, indent=2)

        result_overview += "*********************************************" + "\n"
        result_overview += "Results for " + classification_file + " with LLM type " + llm + "\n"
        result_overview += "*********************************************" + "\n"
        result_overview += "True positives: " + str(countTP) + "\n"
        result_overview += "False negatives: " + str(countFN) + "\n"
    else:
        with open(output_file + '/TN_list_' + llm +  "_" + class_file, "w") as output: 
            json.dump(TN_list, output, indent=2)

        with open(output_file + '/FP_list_' + llm +  "_" + class_file, "w") as output:
            json.dump(FP_list, output, indent=2)

        result_overview += "*********************************************\n"
        result_overview += "Results for " + classification_file + " with LLM type " + llm + "\n"
        result_overview += "*********************************************\n"
        result_overview += "True negatives: " + str(countTN) + "\n"
        result_overview += "False positives: " + str(countFP) + "\n"

    result_overview += "Correct classification results: " + str(correct_classification) + "\n"
    result_overview += "Partially correct classification results: " + str(partially_correct_classification) + "\n"
    result_overview += "Incorrect classification results: " + str(incorrect_classification) + "\n"
    result_overview += "No request sent: " + str(no_request) + "\n"
    result_overview += "\n"
    result_overview += correct_attack_types(correctly_classified, partially_correctly_classified, incorrectly_classified, attack_types_lines)
    result_overview += "\n"
    result_overview += false_negatives_attack_types(FN_list, attack_types_lines)

    with open(output_file + llm + "_" + class_file.split(".")[0] + ".txt", "w") as overview:
        overview.write(result_overview)