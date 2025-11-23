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


def count_and_match(data, num_idx, match_fun) -> list[int]:
    
    result = np.zeros(num_idx, dtype=int)
    for item in data:
        run_nr = int(item['run'])
        if int(data[-1]['run']) > len(data) + 1:
            run_nr = int((run_nr) / 5)
            
        for entry in item['data']:
            if match_fun(entry):
                result[run_nr - 1] += 1
    return result.tolist()



def simple_count(data, num_runs) -> list[int]:
    result = np.zeros(num_runs, dtype=int)
    for item in data:
        run_nr = int(item['run'])
        if int(data[-1]['run']) > num_runs + 1:
            run_nr = int((run_nr) / 5)
    
        result[run_nr-1] = len(item['data'])
        
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

    num_runs = 0
    for _, dirnames, _ in os.walk("."):
        num_runs += len(dirnames)

    print(num_runs)
    return data, num_runs

def join_and_read_files(paths):
    data = []
    entry = {}
    for f in paths:
        with open(f, "r") as file:
            entry = json.loads(file.read())
            run_number = f[2:].split("_")[0]
            data.append({"run": run_number, "data": entry})

    sorted_data = sorted(data, key = lambda x: int(x['run']))
    return sorted_data



def main():

    data, num_runs = collect_files()

    colors = {
        'FN': CSS4_COLORS["red"],
        'IC': CSS4_COLORS["gold"],
        'PC': CSS4_COLORS["yellowgreen"],
        'CC': CSS4_COLORS["darkgreen"],
        'TN': CSS4_COLORS["darkgreen"],
        'FP': CSS4_COLORS["red"]
    }

    for model in models:
        for provider in data_provider:
            cur_data = list(map(lambda d: d[model][provider], data))
            tp = join_and_read_files(list(map(lambda d: d['TP'], cur_data)))
            fn = join_and_read_files(list(map(lambda d: d['FN'], cur_data)))
            fp = join_and_read_files(list(map(lambda d: d['FP'], cur_data)))
            tn = join_and_read_files(list(map(lambda d: d['TN'], cur_data)))

            diagram_1 = {
                'FN': simple_count(fn, num_runs),
                'IC': count_and_match(tp, num_runs, lambda x: x['classification_correct'].startswith('Incorrect classification')),
                'PC': count_and_match(tp, num_runs, lambda x: x['classification_correct'].startswith('Partially correct classification')),
                'CC': count_and_match(tp, num_runs, lambda x: x['classification_correct'].startswith('Correct classification')),
            }

            print(diagram_1)
            
            diagram_2 = {
                'TN': simple_count(tn, num_runs),
                'FP': simple_count(fp, num_runs)
            }

            print(diagram_2)

            plot(diagram_1, f"Classification performance with increasing number of additional log lines: LLM - {model}, Data set - {provider} - attacks", "Runs", "Classifications", list(map(str, range(1, num_runs + 1))), colors)
            plot(diagram_2, f"Classification performance with increasing number of additional log lines: LLM - {model}, Data set - {provider} - no attacks", "Runs", "Classifications", list(map(str, range(1, num_runs + 1))), colors)


def plot(data: dict[str, list[int]], title: str, xlabel: str, ylabel: str, names: list[str], colors):

    width = 0.5

    _fig, ax = plt.subplots(figsize=(12,5))
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
    plt.tight_layout
    plt.show()


if __name__ == '__main__':
    main()
