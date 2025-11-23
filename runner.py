import os
import subprocess

llms = ["chatgpt", "gemini"]
base_input = "./preprocessing_files/"
runs = ["zero_shot", "one_shot"]


for run in runs:
    for llm in llms:

        input_dir = f"{base_input}{run}/consistency/{llm}"
        files = list(map(lambda x: os.path.join(input_dir, x), os.listdir(input_dir)))
        for file in files:
            script = "./utility/automated_evaluate_LLM_preinterpretation.py"
            tech_file = "./utility/mitre_attack_techniques.json"
            scrapper = file.split("/")[-1].split("_")[0]
            output = f"./anomaly_preprocessing/results/LLM_preinterpretation/{run}/"
            cmd = f"./proto_venv/bin/python3 {script} --technique_file {tech_file} --test_data_file {scrapper}_attack_lines.json --mapping_file ./utility/attack_types_to_mitre.json --llm_type {llm} --attacks y --run consistency --classification_file {file} --output {output}"
            subprocess.run(cmd.split(" "))
            print(cmd)
            print("\n")
