"""
Evaluate the consistency of runs with the same input by computing a Wilson Score confidence interval
"""

import argparse
import os
import json
import matplotlib.pyplot as plt
from scipy.stats import norm
from math import sqrt
from collections import Counter, defaultdict
import re


def create_run_summary(eval_results: list, attacks: bool):
    pattern = r'(0[1-9]|[12][0-9]|3[01])_(0[1-9]|1[0-2])_(\d{4})_([01][0-9]|2[0-3])_([0-5][0-9])'
    file_name = eval_results[1].replace("Results for ", "").replace(" with LLM type chatgpt", "")
    
    summary = {
        "run_nr": re.search(pattern, file_name)[0],
        "llm": file_name.split("/")[-2],
        "dataset": file_name.split("/")[-1].split("_")[0],
    }

    if attacks:
        summary["tp"] = int(eval_results[3].split(":")[1].strip())
        summary["fn"] = int(eval_results[4].split(":")[1].strip())
        summary["cc"] = int(eval_results[5].split(":")[1].strip())
        summary["pc"] = int(eval_results[6].split(":")[1].strip())
        summary["ic"] = int(eval_results[7].split(":")[1].strip())
    else:
        summary["fp"] = int(eval_results[3].split(":")[1].strip())
        summary["tn"] = int(eval_results[4].split(":")[1].strip())
    return summary

def wilson_score_interval(successes, total, confidence=0.95):
    if total == 0:
        return (0, 0)
    
    z = norm.ppf(1 - (1 - confidence) / 2)

    p_hat = successes / total

    denominator = 1 + z**2 / total
    center = p_hat + z**2 / (2 * total)
    margin = z * sqrt((p_hat * (1 - p_hat) + z**2 / (4 * total)) / total)
    lower = (center - margin) / denominator
    upper = (center + margin) / denominator
    return p_hat, lower, upper

def determine_consistency(combos, runs, attacks):
    combo_counts = Counter(combos)
    majority_combo, majority_count = combo_counts.most_common(1)[0]

    consistent_runs = [run for run, combo in zip(runs, combos) if combo == majority_combo]

    total = len(runs)
    successes = len(consistent_runs)
    consistency_rate = successes / total if total > 0 else 0.0
    p_hat, lower, upper = wilson_score_interval(successes, total)

    if attacks:
        majority_state = {
            "tp": majority_combo[0],
            "fn": majority_combo[1],
        }

        if len(majority_combo) > 2:
            majority_state["cc"] = majority_combo[2],
            majority_state["pc"] = majority_combo[3],
            majority_state["ic"] = majority_combo[4]
    else:
        majority_state = {
            "fp": majority_combo[0],
            "tf": majority_combo[1]
        }
    
    return {
        "majority_state": majority_state,
        "consistent_runs": [r["run_nr"] for r in consistent_runs],
        "successes": successes,
        "total": total,
        "consistency_rate": consistency_rate,
        "wilson_interval": (lower, upper),
        "p_hat": p_hat
    }

def plot_diagram(lower, upper, p_hat, total, successes, llm, dataset, details, save_file):
    plt.figure(figsize=(7, 6))
    plt.hlines(1, 0, 1, colors='lightgray', linestyles='--')
    plt.hlines(1, lower, upper, colors='steelblue', lw=8, label='Wilson CI')
    plt.plot(p_hat, 1, 'o', color='darkorange', label='Observed proportion')
    plt.xlim(0, 1)
    plt.ylim(0.8, 1.2)
    plt.xlabel('True proportion (consistency rate)')
    plt.yticks([])
    plt.legend()
    plt.title(f"Wilson 95% Confidence Interval\nn={total}, successes={successes}\n{llm} - {dataset} - {details}")
    plt.savefig(f'{save_file}.png')

def main():
    parser = argparse.ArgumentParser(
        description='Check consistency of runs with same input.',
        formatter_class=argparse.RawTextHelpFormatter
    )
    
    parser.add_argument(
        '--experiment_folder', 
        type=str, 
        required=True,
        help='Path to the folder containing the evaluation results that should be checked for consistency.'
    )
    
    args = parser.parse_args()
    folder_path = args.experiment_folder

    run_summaries_no_attack = []
    run_summaries_attack = []

    for path, _, files in os.walk(folder_path):
        for name in files:
            if name.endswith(".txt"):
                with open(os.path.join(path, name), "r") as file:
                    lines = file.readlines()
                    if "no_attack" in name:
                        run_summaries_no_attack.append(create_run_summary(lines, False))
                    else:
                        run_summaries_attack.append(create_run_summary(lines, True))

    attack_groups = defaultdict(list)
    for run in run_summaries_attack:
        key = (run["llm"], run["dataset"])
        attack_groups[key].append(run)

    no_attack_groups = defaultdict(list)
    for run in run_summaries_no_attack:
        key = (run["llm"], run["dataset"])
        no_attack_groups[key].append(run)

    exp_name = folder_path.split("LLM_preinterpretation")[1].replace("/", "_")

    attack_all_classifications_results = []
    attack_only_tp_fn_results = []
    no_attack_results = []


    plot_file = folder_path + "/attack_runs_all_classifications"
    for (llm, dataset), group_runs in attack_groups.items():
        attack_combos = [tuple(run[field] for field in ['tp', 'fn', 'cc', 'pc', 'ic']) for run in group_runs]
        result = determine_consistency(attack_combos, group_runs, True)
        result["llm"] = llm
        result["dataset"] = dataset
        attack_all_classifications_results.append(result)
        plot_diagram(lower=result["wilson_interval"][0], 
                     upper=result["wilson_interval"][1], 
                     p_hat=result["p_hat"], 
                     total=result["total"], 
                     successes=result["successes"], 
                     llm=llm, 
                     dataset=dataset, 
                     details="Attacks detailed", 
                     save_file= f"{folder_path}/attack_detailed_{llm}_{dataset}")

    for (llm, dataset), group_runs in attack_groups.items():
        attack_combos = [tuple(run[field] for field in ['tp', 'fn']) for run in group_runs]
        result = determine_consistency(attack_combos, group_runs, True)
        result["llm"] = llm
        result["dataset"] = dataset
        attack_only_tp_fn_results.append(result)
        plot_diagram(lower=result["wilson_interval"][0], 
                     upper=result["wilson_interval"][1], 
                     p_hat=result["p_hat"], 
                     total=result["total"], 
                     successes=result["successes"], 
                     llm=llm, 
                     dataset=dataset, 
                     details="Attacks tp-fn", 
                     save_file= f"{folder_path}/attack_tp_fn_{llm}_{dataset}")

    for (llm, dataset), group_runs in no_attack_groups.items():
        no_attack_combos = [tuple(run[field] for field in ['fp', 'tn']) for run in group_runs]
        result = determine_consistency(no_attack_combos, group_runs, False)
        result["llm"] = llm
        result["dataset"] = dataset
        no_attack_results.append(result)
        plot_diagram(lower=result["wilson_interval"][0], 
                     upper=result["wilson_interval"][1], 
                     p_hat=result["p_hat"], 
                     total=result["total"], 
                     successes=result["successes"], 
                     llm=llm, 
                     dataset=dataset, 
                     details="No attacks", 
                     save_file= f"{folder_path}/no_attacks_{llm}_{dataset}")
    
    with open(folder_path + "/attack_runs_all_classifications" + exp_name + ".json", "w") as output:
        json.dump(attack_all_classifications_results, output, indent=4)
    
    with open(folder_path + "/attack_runs_only_tp_fn" + exp_name + ".json", "w") as output:
        json.dump(attack_only_tp_fn_results, output, indent=4)

    with open(folder_path + "/no_attack_runs" + exp_name + ".json", "w") as output:
        json.dump(no_attack_results, output, indent=4)

if __name__ == '__main__':
    main()