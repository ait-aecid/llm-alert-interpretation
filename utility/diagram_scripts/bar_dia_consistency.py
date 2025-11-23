import os
import json
from matplotlib.ticker import MaxNLocator
import numpy as np
import matplotlib.pyplot as plt
from matplotlib.colors import CSS4_COLORS


runs_dir = '.'
models = ['chatgpt', 'gemini']
data_provider = ['aminer', "wazuh"]
declarations = ['TP', 'FN']
num_lines = 100
attack_types = ['DNSteal', 'Network Scans', 'Service Scans', 'WPscan', 'Dirb', 'Webshell', 'Password Cracking', 'Privilege Escalation', 'Reverse Shell']
def attack_type_idx(item):
    return [x.lower().replace(' ', '') for x in attack_types].index(item['attack_type'])




def count_and_match(data, idx_fun, num_idx, match_fun) -> list[int]:
    
    result = np.zeros(num_idx, dtype=int)
    for item in data:
        line_nr = idx_fun(item) 
        if match_fun(item):
            result[line_nr] += 1
    return result.tolist()



def simple_count(data) -> list[int]:
    result = np.zeros(num_lines, dtype=int)
    for item in data:
        line_nr= item['line_number']
        result[line_nr - 1] += 1
    return result.tolist()



def collect_files():
    run_folders = filter(lambda f: os.path.isdir(f) and not f.startswith('.'), os.listdir(runs_dir))
    data: list[dict[str, dict[str, dict[str, str]]]] = []
    for run_folder in run_folders:
        files = os.listdir(os.path.join(runs_dir, run_folder))
        
        run_entry: dict[str, dict[str, dict[str, str]]] = {}
        for model in models:

            run_entry[model] = {}
            for provider in data_provider:
                filtered_files = list(filter(lambda f: model in f and provider in f, files))
                entry = {
                    'TP': os.path.join(runs_dir, run_folder, next(filter(lambda f: f.startswith('TP'), filtered_files))),
                    'FP': os.path.join(runs_dir, run_folder, next(filter(lambda f: f.startswith('FP'), filtered_files))),
                    'TN': os.path.join(runs_dir, run_folder, next(filter(lambda f: f.startswith('TN'), filtered_files))),
                    'FN': os.path.join(runs_dir, run_folder, next(filter(lambda f: f.startswith('FN'), filtered_files))),
                }
                run_entry[model][provider] = entry
        data.append(run_entry)

    return data

def join_and_read_files(paths):
    data = []
    for f in paths:
        with open(f, "r") as f:
            data += json.loads(f.read())

    return data



def main():

    data = collect_files()

    colors = {
        'FN': CSS4_COLORS["red"],
        'IC': CSS4_COLORS["gold"],
        'PC': CSS4_COLORS["yellowgreen"],
        'CC': CSS4_COLORS["darkgreen"],
        'TN': CSS4_COLORS["darkgreen"],
        'FP': CSS4_COLORS["red"]
    }

    for model in models:
        print(model)
        for provider in data_provider:
            print(provider)
            cur_data = list(map(lambda d: d[model][provider], data))
            tp = join_and_read_files(list(map(lambda d: d['TP'], cur_data)))
            fp = join_and_read_files(list(map(lambda d: d['FP'], cur_data)))
            tn = join_and_read_files(list(map(lambda d: d['TN'], cur_data)))
            fn = join_and_read_files(list(map(lambda d: d['FN'], cur_data)))

            diagram_1 = {
                'FN': simple_count(fn),
                'IC': count_and_match(tp, lambda x: x['line_number'] - 1, num_lines, lambda x: x['classification_correct'].startswith('Incorrect classification')),
                'PC': count_and_match(tp,lambda x: x['line_number'] - 1, num_lines, lambda x: x['classification_correct'].startswith('Partially correct classification')),
                'CC': count_and_match(tp,lambda x: x['line_number'] - 1, num_lines, lambda x: x['classification_correct'].startswith('Correct classification')),
            }

            diagram_2 = {
                'TN': simple_count(tn),
                'FP': simple_count(fp)
            }

            diagram_3 = {
                'FN': count_and_match(fn, attack_type_idx, len(attack_types), lambda _: True),
                'IC': count_and_match(tp, attack_type_idx, len(attack_types), lambda x: x['classification_correct'].startswith('Incorrect classification')),
                'PC': count_and_match(tp, attack_type_idx, len(attack_types), lambda x: x['classification_correct'].startswith('Partially correct classification')),
                'CC': count_and_match(tp, attack_type_idx, len(attack_types), lambda x: x['classification_correct'].startswith('Correct classification')),
            }

            plot(diagram_1, f"Classification of alerts in different runs: LLM - {model}, Data set - {provider} - attacks", "Alerts", "Runs", list(map(str, range(1, num_lines + 1))), colors)
            plot(diagram_2, f"Classification of alerts in different runs: LLM - {model}, Data set - {provider} - no attacks", "Alerts", "Runs", list(map(str, range(1, num_lines + 1))), colors)
            plot(diagram_3, f"Classification of alerts in different runs depending on attack: LLM - {model}, Data set - {provider}", "Attack Types", "Classifications", attack_types, colors) 

def plot(data: dict[str, list[int]], title: str, xlabel: str, ylabel: str, names: list[str], colors):

    width = 0.8

    _fig, ax = plt.subplots(figsize=(20,6)) # 12, 6
    ax.yaxis.set_major_locator(MaxNLocator(integer=True))
    bottom = np.zeros(len(list(data.items())[0][1]), dtype=int)

    for boolean, weight_count in data.items():
        p = ax.bar(names, weight_count, width, label=boolean, bottom=bottom, color=colors[boolean])
        bottom += weight_count

    ax.set_title(title)
    ax.legend(loc="upper right")
    plt.xticks(rotation=90)
    plt.xlabel(xlabel)
    plt.ylabel(ylabel)
    plt.tight_layout()
    plt.show()


if __name__ == '__main__':
    main()
