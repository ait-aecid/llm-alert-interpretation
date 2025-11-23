"""
Count evaluation result classifications per category (Too generic, aligns with IDS alert but not label,...) for multiple CSV files

Usage:
    python automated_evaluate_zero_unrestricted.py /path/to/folder
    python automated_evaluate_zero_unrestricted.py file1.csv file2.tsv
"""

from collections import defaultdict
import matplotlib.pyplot as plt
import csv
import os
import argparse
import json

categories = ["Too generic", "Correct & expressive", "Incorrect", "Alternate explanation for alert"]
colors = {"Correct & expressive": "green", "Alternate explanation for alert": "yellow", "Too generic": "orange", "Incorrect": "red"}
order = ["Correct & expressive", "Alternate explanation for alert", "Too generic", "Incorrect"]

def count_classifications_per_attack_type(results):
    counts_by_attack = defaultdict(lambda: defaultdict(int))
    for entry in results:
        counts_by_attack[entry["attack_type"].strip()][entry["classification"].strip()] += entry["occurrence_count"]
    return {a: dict(c) for a, c in counts_by_attack.items()}

def count_classifications_total(results):
    total_counts = defaultdict(int)
    for entry in results:
        total_counts[entry["classification"]] += entry["occurrence_count"]
    return dict(total_counts)

def collect_interpretation_texts_per_attack_type(results):
    interpretations_by_attack = defaultdict(list)
    for entry in results:
        interpretations_by_attack[entry["attack_type"]] = entry["interpretation_text"]
    return dict(interpretations_by_attack)

def _add_stacked_labels(ax, x_positions, values_by_class, bottoms_by_class):
    for i, cls in enumerate(order):
        for j, (x, val, bottom) in enumerate(zip(x_positions, values_by_class[cls], bottoms_by_class[cls])):
            if val > 0:
                ax.text(
                    x, bottom + val / 2,
                    str(val),
                    ha="center", va="center",
                    fontsize=9, color="black"
                )

def plot_total_classifications(total_counts_list, labels, save_file):
    x = list(range(len(total_counts_list)))
    fig, ax = plt.subplots(figsize=(10, 10))

    values_by_class = {cls: [d.get(cls, 0) for d in total_counts_list] for cls in order}
    bottoms_by_class = {cls: [0] * len(total_counts_list) for cls in order}

    bottoms = [0] * len(total_counts_list)
    for cls in order:
        values = values_by_class[cls]
        color = colors.get(cls, "gray")
        ax.bar(x, values, bottom=bottoms, label=cls, color=color)
        bottoms_by_class[cls] = bottoms.copy()
        bottoms = [b + v for b, v in zip(bottoms, values)]

    _add_stacked_labels(ax, x, values_by_class, bottoms_by_class)

    ax.set_xticks(x)
    ax.set_xticklabels(labels, rotation=30, ha="right")
    ax.set_ylabel("Occurrences")
    ax.set_title("Total Classification Counts per Run")
    plt.legend(title="Classification", loc="upper right", bbox_to_anchor=(0.98, 0.98), frameon=True)

    max_val = max(bottoms) if bottoms else 0
    ax.set_ylim(0, max_val * 1.1)
    plt.tight_layout()
    plt.savefig(f'{save_file}.png')

def plot_classifications_per_attack(counts_by_attack, save_file, run_nr, llm, dataset):
    fig, ax = plt.subplots(figsize=(10, 6))

    attack_types = list(counts_by_attack.keys())
    bottoms = [0] * len(attack_types)

    values_by_class = {cls: [counts_by_attack[a].get(cls, 0) for a in attack_types] for cls in order}
    bottoms_by_class = {cls: [0] * len(attack_types) for cls in order}

    for cls in order:
        values = values_by_class[cls]
        color = colors.get(cls, "gray")
        ax.bar(attack_types, values, bottom=bottoms, color=color, label=cls)
        bottoms_by_class[cls] = bottoms.copy()
        bottoms = [b + v for b, v in zip(bottoms, values)]

    _add_stacked_labels(ax, range(len(attack_types)), values_by_class, bottoms_by_class)

    ax.set_xticks(range(len(attack_types)))
    ax.set_xticklabels(attack_types, rotation=30, ha="right")

    ax.set_ylabel("Occurrences")
    ax.set_xlabel("Attack Type")
    ax.set_title(f"Classification Counts per Attack Type:\nRun {run_nr}:{llm}-{dataset}")

    max_val = max(bottoms) if bottoms else 0
    ax.set_ylim(0, max_val * 1.1)
    ax.yaxis.get_major_locator().set_params(integer=True)

    ax.legend(title="Classification", loc="upper right", bbox_to_anchor=(0.95, 0.95), frameon=True)

    plt.tight_layout()
    plt.savefig(f'{save_file}.png')

def main():
    parser = argparse.ArgumentParser(
        description='Count classification results in total and per attack type. Collect interpretation texts.',
        formatter_class=argparse.RawTextHelpFormatter
    )
    
    parser.add_argument(
        '--result_folder', 
        type=str, 
        required=True,
        help='Path to the folder containing the interpretation results that should be evaluated.'
    )
    
    args = parser.parse_args()
    folder_path = args.result_folder        

    evaluations = []
    interpretation_texts = []

    folder = "../anomaly_preprocessing/results/LLM_preinterpretation/zero_shot_unrestricted"
    
    for path, _, files in os.walk(folder_path):
        for name in files:
            if name.endswith(".csv"):
                results = []

                with open(os.path.join(path, name), "r") as file:
                    csvreader = csv.reader(file, delimiter=';')
                    next(csvreader, None) # skip header line

                    for row in csvreader:
                        if not row[0]:
                            continue
                        results.append({
                            "attack_type": row[0],
                            "occurrence_count": int(row[1]),
                            "interpretation_text": row[2].replace(",", "").split("\n"),
                            "classification": row[5]
                        })

                name = name.split("_")
                run_nr = name[0]
                dataset = name[1]
                llm = name[2].replace(".csv", "")

                classifications_total = count_classifications_total(results)
                classifications_per_attack_type = count_classifications_per_attack_type(results)

                plot_classifications_per_attack(classifications_per_attack_type, f"{folder}/class_count_per_attack_type_{run_nr}_{dataset}_{llm}", run_nr, llm, dataset)

                evaluations.append({
                    "run_nr": run_nr,
                    "dataset": dataset,
                    "llm": llm,
                    "classifications_total": classifications_total,
                    "classifications_per_attack_type": classifications_per_attack_type,
                })

                interpretation_texts.append(collect_interpretation_texts_per_attack_type(results))

    sorted_evaluations = sorted(evaluations, key=lambda d: d.get('classifications_total', {}).get('Correct & expressive', 0), reverse=True)
    evaluation_data = [data["classifications_total"] for data in sorted_evaluations]
    evaluation_labels = [f"{data["run_nr"]}-{data["dataset"]}-{data["llm"]}" for data in sorted_evaluations] 
    plot_total_classifications(evaluation_data, evaluation_labels, folder + "/total_class_count")

    with open(folder + "/unrestricted_zero.json", "w") as output:
        json.dump(evaluations, output, indent=4)

    merged = {}
    for d in interpretation_texts:
        for key, values in d.items():
            merged.setdefault(key, []).extend(v.strip() for v in values)


    for key in merged:
        seen = set()
        merged[key] = [v for v in merged[key] if not (v in seen or seen.add(v))]

    with open(folder + "/interpretation_texts_per_attack_type.json", "w") as output:
        json.dump(merged, output, indent=4)

if __name__ == "__main__":
    main()