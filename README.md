# LLM-Based IDS Alert Interpretation

## Description

This repository contains all data generation scripts, evaluation scripts, raw and processed datasets, and visualizations created during the experiments for the publications listed in the **Publications** section.

---

## Requirements

The scripts were developed and tested on **Ubuntu Linux** using:

- **Python 3.12.3**
- Python modules listed in [`requirements.txt`](./requirements.txt)

---

## Folder Structure

```text
LLM-Based-IDS-Alert-Interpretation/
├── anomaly_preprocessing/
│   ├── results/                     # Per-experiment results + diagrams
│   └── anomaly_preprocessor.py      # Used for preliminary full-text search experiments
│
├── cti_preprocessing/               # Preliminary experiments, uses AttacKG for CTI extraction
│
├── mapping/                         # Used for preliminary full-text search experiments
│
├── preprocessing_files/             # IoC extraction files + LLM interpretations (by experiment)
│
├── test_data/
│   ├── alerts from "AIT Alert Data Set"
│   ├── reports for preliminary experiments
│   └── few-shot examples
│
├── utility/                         # Data generation, evaluation, and diagram scripts
│
├── llm_keys/                        # Insert your OpenAI / Gemini API keys here
│
├── main.py                          # Used during preliminary full-text search experiments
├── requirements.txt                 # All required Python modules
└── LICENSE                          # Project license (EUPL)
```

## Usage

To run the data generation scripts in the `utility` folder:

1. Obtain valid **OpenAI** and/or **Google Gemini** API keys.
2. Place them into the corresponding `.txt` files inside the `llm_keys/` folder.
3. Ensure your API account has sufficient token quota.

### Generation Scripts

Naming pattern:
`automated_<LLM>_api_processing_<experiment>.py`

Generated outputs are stored in:
`preprocessing_files/`

### Evaluation Scripts

Naming pattern:
`automated_evaluate_<usage>.py`

Evaluation results are stored in:
`anomaly_preprocessing/results/`

---

## Publications

---

## 📄 License

This project is licensed under the **European Union Public License (EUPL)**.
Full text:
`LICENSE` — https://github.com/ait-aecid/llm-alert-interpretation/blob/main/LICENSE
