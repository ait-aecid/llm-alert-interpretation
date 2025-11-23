"""
This utility script calculates scoring metrics to compare different runs of the same experiment with each other.
It ranks the different runs to make them comparable.
"""
import argparse
import os
import json
import matplotlib.pyplot as plt
from matplotlib.patches import Patch

# single run metrics
def true_positive_rate(tp, fn):
    return tp / (tp + fn)

def false_positive_rate(tn, fp):
    return fp / (fp + tn)

def CC_and_PC_to_IC_and_FN(cc, pc, ic, fn):
    return (cc + pc) / (cc + pc + ic + fn)


# attack and no attack combination metrics
def accuracy(tp, tn, fp, fn):
    return (tp + tn) / (tp + tn + fp + fn)

def precision(tp, fp):
    return tp / (tp + fp)

def f1(precision, tp_rate):
    return 2 * (precision * tp_rate / (precision + tp_rate))

def create_run_summary(eval_results: list, attacks: bool):
    file_name = eval_results[1].replace("Results for ", "").replace(" with LLM type chatgpt", "")
    summary = {
        "run_nr": file_name.split("/")[-3],
        "llm": file_name.split("/")[-2],
        "dataset": file_name.split("/")[-1].split("_")[0],
    }

    if attacks:
        tp = int(eval_results[3].split(":")[1].strip())
        fn = int(eval_results[4].split(":")[1].strip())
        cc = int(eval_results[5].split(":")[1].strip())
        pc = int(eval_results[6].split(":")[1].strip())
        ic = int(eval_results[7].split(":")[1].strip())

        summary["tp_rate"] = true_positive_rate(tp, fn)
        summary["correct_to_incorrect"] = CC_and_PC_to_IC_and_FN(cc, pc, ic, fn)
        summary["tp"] = tp
        summary["fn"] = fn
        summary["cc"] = cc
        summary["pc"] = pc
        summary["ic"] = ic
    else:
        tn = int(eval_results[3].split(":")[1].strip())
        fp = int(eval_results[4].split(":")[1].strip())

        summary["fp_rate"] = false_positive_rate(tn, fp)
        summary["fp"] = fp
        summary["tn"] = tn
    return summary

def plot_diagram(data_list, values, ylabel, title):
    color_map = {
        ("chatgpt", "aminer"): "royalblue",
        ("chatgpt", "wazuh"): "skyblue",
        ("gemini", "aminer"): "orange",
        ("gemini", "wazuh"): "gold",
    }

    legend_elements = [
        Patch(facecolor="royalblue", label="ChatGPT - Aminer"),
        Patch(facecolor="skyblue", label="ChatGPT - Wazuh"),
        Patch(facecolor="orange", label="Gemini - Aminer"),
        Patch(facecolor="gold", label="Gemini - Wazuh"),
    ]

    labels = [f"{r['llm']}-{r['dataset']}{r['run_nr']}" for r in data_list]

    colors = [color_map[(r["llm"], r["dataset"])] for r in data_list]
    plt.figure(figsize=(10, 6))
    plt.bar(range(len(data_list)), values, color=colors)
    plt.xticks(range(len(data_list)), labels, rotation=45, ha="right")
    plt.ylabel(ylabel)
    plt.title(title)
    plt.legend(handles=legend_elements, title="LLM + Dataset")
    plt.tight_layout()
    plt.show()

def main():
    parser = argparse.ArgumentParser(
        description='Compare and rank different runs of the same experiment.',
        formatter_class=argparse.RawTextHelpFormatter
    )

    parser.add_argument(
        '--experiment_folder',
        type=str,
        required=True,
        help='Path to the folder containing the evaluation results that should be used to rank the runs.'
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

    # single run metrics
    sorted_attack_list_correct_to_incorrect = sorted(run_summaries_attack, key=lambda x: x["correct_to_incorrect"], reverse=True)
    sorted_attack_list_tp_to_fn = sorted(run_summaries_attack, key =lambda x: x["tp_rate"], reverse=True)
    sorted_no_attack_list = sorted(run_summaries_no_attack, key=lambda x: x["fp_rate"], reverse=True)

    exp_name = folder_path.split("LLM_preinterpretation")[1].replace("/", "_")
    with open(folder_path + "/ranked_attack_runs" + exp_name + "_c_to_ic.json", "w") as output:
        json.dump(sorted_attack_list_correct_to_incorrect, output, indent=4)

    with open(folder_path + "/ranked_attack_runs" + exp_name + "_tp_to_fn.json", "w") as output:
        json.dump(sorted_attack_list_tp_to_fn, output, indent=4)

    with open(folder_path + "/ranked_no_attack_runs" + exp_name + ".json", "w") as output:
        json.dump(sorted_no_attack_list, output, indent=4)

    correct_to_incorrect = [c["correct_to_incorrect"] for c in sorted_attack_list_correct_to_incorrect]
    plot_diagram(sorted_attack_list_correct_to_incorrect, correct_to_incorrect, "Correct-to-incorrect Ratio", "Correct-to-incorrect Ratio Runs Ranked (Highest to Lowest)")

    tp_rate = [t["tp_rate"] for t in sorted_attack_list_tp_to_fn]
    plot_diagram(sorted_attack_list_tp_to_fn, tp_rate, "TP-Rate", "TP-Rate Runs Ranked (Highest to Lowest)")

    fp_rate = [f["fp_rate"] for f in sorted_no_attack_list]
    plot_diagram(sorted_no_attack_list, fp_rate, "FP-Rate", "FP-Rate Runs Ranked (Highest to Lowest)")

    # combined metrics - attacks & no attacks
    comb_sort_attack = sorted(run_summaries_attack, key = lambda x: (x["run_nr"], x["llm"], x["dataset"]))
    comb_sort_no_attack = sorted(run_summaries_no_attack, key = lambda x: (x["run_nr"], x["llm"], x["dataset"]))

    combined_metrics = []
    for i in range(0,len(comb_sort_attack)):
        tp = comb_sort_attack[i]["tp"]
        tn = comb_sort_no_attack[i]["tn"]
        fp = comb_sort_no_attack[i]["fp"]
        fn = comb_sort_attack[i]["fn"]

        p = precision(tp, fp)
        tp_r = true_positive_rate(tp, fn)

        run_score = {
            "run_nr": comb_sort_attack[i]["run_nr"],
            "llm": comb_sort_attack[i]["llm"],
            "dataset": comb_sort_attack[i]["dataset"],
            "f1": f1(p, tp_r),
            "accuracy": accuracy(tp, tn, fp, fn),
            "precision": p
        }
        combined_metrics.append(run_score)

    accuracy_sort = sorted(combined_metrics, key = lambda x: (x["accuracy"]), reverse=True)
    precision_sort = sorted(combined_metrics, key = lambda x: (x["precision"]), reverse=True)
    f1_score_sort = sorted(combined_metrics, key = lambda x: (x["f1"]), reverse=True)

    exp_name = exp_name.replace("_", "", 1)
    with open(folder_path + "/" + exp_name + "_accuracy.json", "w") as output:
        json.dump(accuracy_sort, output, indent=4)

    with open(folder_path + "/" + exp_name + "_precision.json", "w") as output:
        json.dump(precision_sort, output, indent=4)

    with open(folder_path + "/" + exp_name + "_f1_score.json", "w") as output:
        json.dump(f1_score_sort, output, indent=4)

    accuracies = [a["accuracy"] for a in accuracy_sort]
    plot_diagram(accuracy_sort, accuracies, "Accuracy", "Accuracy Runs Ranked (Highest to Lowest)")

    precisions = [p["precision"] for p in precision_sort]
    plot_diagram(precision_sort, precisions, "Precision", "Precision Runs Ranked (Highest to Lowest)")

    f1_score = [f["f1"] for f in f1_score_sort]
    plot_diagram(f1_score_sort, f1_score, "F1-Score", "F1-Score Runs Ranked (Highest to Lowest)")

if __name__ == '__main__':
    main()
