import json
attacks = False

print("Filename: ")
filename = input()
print("LLM type: ")
llm = input()
print("Does the file contain attacks? y/n")
attack = input()

if(attack == "y"):
    attacks = True

if attacks:
    original_lines = ""
    line_description = []

    with open('test_data/' + filename, 'r') as file:
        original_lines = file.readlines()
    
    name = filename.split(".")[0]
    with open('test_data/' + name + '_lines.txt', 'r') as file:
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

        attack_types_lines = []
        for i in range(0, len(new_description)):
            for line in new_description[i]:
                attack_types_lines.append(attack_types[i].lower())

    countTP = 0
    TP_list = []
    countFN = 0
    FN_list=[]

    with open('preprocessing_files/' + llm + "_" + filename, 'r') as processed:
        processed_lines = json.load(processed)

        for i in range(0, len(processed_lines)):
            if processed_lines[i]["classification"] == "TP":
                countTP += 1
                TP_list.append({
                    "predicted_attack_type": processed_lines[i]["attack_type"],
                    "attack_type": attack_types_lines[i],
                    "description": processed_lines[i]["description"],
                    "tools": processed_lines[i]["tools"],
                    "anomaly": original_lines[i]
                })
            else: 
                countFN += 1
                FN_list.append({
                    "predicted_attack_type": processed_lines[i]["attack_type"],
                    "attack_type": attack_types_lines[i],
                    "description": processed_lines[i]["description"],
                    "tools": processed_lines[i]["tools"],
                    "anomaly": original_lines[i]
                })

    with open('outputs/TP_list_' + llm +  "_" + filename, "w") as output:  
        json.dump(TP_list, output, indent=2)
    
    with open('outputs/FN_list_' + llm +  "_" + filename, "w") as output: 
        json.dump(FN_list, output, indent=2)

    print("*********************************************")
    print("Results for ", filename, " with LLM type ", llm)
    print("*********************************************")
    print("True positives: ", countTP)
    print("False negatives: ", countFN, "\n")

else:
    original_lines = ""
    with open('test_data/' + filename , 'r') as file:
        original_lines = file.readlines()

    countTN = 0
    TN_list = []
    countFP = 0
    FP_list = []

    with open('preprocessing_files/' + llm + "_" + filename, 'r') as processed:
        processed_lines = json.load(processed)

        for i in range(0, len(processed_lines)):
            if processed_lines[i]["classification"] == "TP":
                countFP += 1
                FP_list.append({
                    "attack_type": processed_lines[i]["attack_type"],
                    "description": processed_lines[i]["description"],
                    "tools": processed_lines[i]["tools"],
                    "anomaly": original_lines[i]
                })
            else: 
                countTN += 1
                TN_list.append({
                    "attack_type": processed_lines[i]["attack_type"],
                    "description": processed_lines[i]["description"],
                    "tools": processed_lines[i]["tools"],
                    "anomaly": original_lines[i]
                })

    with open('outputs/TN_list_'  + llm +  "_" + filename, "w") as output: 
        json.dump(TN_list, output, indent=2)

    with open('outputs/FP_list_'  + llm +  "_" + filename, "w") as output:
        json.dump(FP_list, output, indent=2)

    print("*********************************************")
    print("Results for ", filename)
    print("*********************************************")
    print("True negatives: ", countTN)
    print("False positives: ", countFP, "\n")