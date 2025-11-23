import argparse
import sys
import json
import os

from tqdm import tqdm

from cti_preprocessing.cti_processor import CTIProcessor
from cti_preprocessing.mode import CTIProcessingMode
from anomaly_preprocessing.anomaly_processor import AnomalyProcessor
from anomaly_preprocessing.mode import AnomalyProcessingMode
from mapping.mapper import Mapper
from mapping.mode import MappingMode

def process_CTI(preprocessing_mode, inputs):
    processed_CTI = []
    processor = CTIProcessor(preprocessing_mode)
    files = inputs.replace(' ', '').split(",")
    file_count = 0
    for f in files:
        file_count += 1
        with open(f, 'r') as file:
            processed_CTI.append(processor.report_to_intermediate(file))

    print('CTI preprocessing is done. ' + str(file_count) + ' files processed.')
    return processed_CTI

def process_anomaly(anomaly, preprocessing_mode, inputfile = None):
    preprocessing_file_exists = False
    if preprocessing_mode is AnomalyProcessingMode.CHATGPT:
        inputfile = inputfile.split("/")[1]
        if os.path.exists('./preprocessing_files/chatgpt_' + inputfile):
            preprocessing_file_exists = True
    elif preprocessing_mode is AnomalyProcessingMode.GEMINI:
        inputfile = inputfile.split("/")[1]
        if os.path.exists('./preprocessing_files/gemini_' + inputfile):
            preprocessing_file_exists = True

    processor = AnomalyProcessor(preprocessing_file_exists, preprocessing_mode)
    return processor.anomaly_to_intermediate(anomaly, inputfile)

def map_anomaly_to_CTI(anomaly, cti, mapping_mode):
    mapper = Mapper(mapping_mode)
    return mapper.find_mappings(anomaly, cti)

def output_result_to_file(output):
    with open('outputs/matches.json' , 'w') as file:
        json.dump(output, file)

def main():
    parser = argparse.ArgumentParser()

    # Anomaly input list & source type (aminer or wazuh)
    parser.add_argument('-AS', '--anomalySources', required=True, type=str, help="Anomaly file name.")
    parser.add_argument('-AC', '--anomalyConfig', required=True, type=str, help="Anomaly config file name.")
    parser.add_argument('-AP', '--anomalyProcessing', required=True, type=str, help="Anomaly preprocessing. Available options: fulltext, chatgpt, gemini")

    # CTI input files
    parser.add_argument('-CS', '--ctiSources', required=True, type=str, help="CTI sources as a comma separated string.")
    # CTI pre-processing method
    parser.add_argument('-CP', '--ctiProcessing', required=True, type=str, help="Available options: fulltext, attackg_graph, attackg_mitre")

    # Environment (context) information inputs
    parser.add_argument('-ES', '--environmentSource', required=False, type=str, help="Environment information sources as a comma separated string.")

    # Anomaly to CTI mapping method
    parser.add_argument('-MM', '--mappingMode', required=True, help="Available options: fulltext, graphalign")

    arguments = parser.parse_args(sys.argv[1:])

    anomaly_file = arguments.anomalySources
    cti_inputs = arguments.ctiSources

    if arguments.environmentSource is not None:
        environment_data = arguments.environmentSource
    else:
        print('No environment source was provided. The environment will therefore not be considered.')

    match arguments.ctiProcessing:
        case 'fulltext':
            cti_processing = CTIProcessingMode.FULL_TEXT
        case 'attackg_graph':
            cti_processing = CTIProcessingMode.ATTACKG_GRAPH
        case 'attackg_mitre':
            cti_processing = CTIProcessingMode.ATTACKG_MITRE
        case 'fulltextEntityIOC':
            cti_processing = CTIProcessingMode.FULL_TEXT_WITH_ENTITY_IOC_EXTR
        case _:
            print('There is no such CTI processing option.')

    processed_cti = process_CTI(cti_processing, cti_inputs)

    match arguments.mappingMode:
            case 'fulltext':
                mapping_mode = MappingMode.FULL_TEXT
            case 'graphalign':
                mapping_mode = MappingMode.GRAPH_ALIGNMENT
            case 'mitre':
                mapping_mode = MappingMode.ATTACK_MAPPING
            case _:
                print('There is no such matching option.')
                return

    with open(anomaly_file, 'r') as file:
        anomalies = file.readlines()
        output = []

        match arguments.anomalyProcessing:
            case 'fulltext':
                for anomaly in tqdm(anomalies):
                    processed_anomaly = process_anomaly(anomaly, AnomalyProcessingMode.FULL_TEXT, arguments.anomalyConfig)
                    output.append(map_anomaly_to_CTI(processed_anomaly, processed_cti, mapping_mode))
            case 'chatgpt':
                processed_anomalies = process_anomaly(anomalies, AnomalyProcessingMode.CHATGPT, anomaly_file)
                for i in tqdm(range(0, len(processed_anomalies))):
                    uninterpreted_anomaly = process_anomaly(anomalies[i], AnomalyProcessingMode.FULL_TEXT, arguments.anomalyConfig)
                    matches = map_anomaly_to_CTI(processed_anomalies[i], processed_cti, mapping_mode)
                    result = {
                        "anomaly_id": uninterpreted_anomaly["id"],
                        "rule": uninterpreted_anomaly["description"],
                        "numResults": len(matches),
                        "results": matches
                    }
                    if "timestamp_format" in anomalies[i].keys():
                        output["anomaly_timestamp"] = anomalies[i]["timestamp_format"]
                    else:
                        output["anomaly_timestamp"] = anomalies[i]["timestamp"]
                    output.append(result)
            case 'gemini':
                processed_anomalies = process_anomaly(anomalies, AnomalyProcessingMode.GEMINI, anomaly_file)
                for i in tqdm(range(0, len(processed_anomalies))):
                    uninterpreted_anomaly = process_anomaly(anomalies[i], AnomalyProcessingMode.FULL_TEXT, arguments.anomalyConfig)
                    matches = map_anomaly_to_CTI(processed_anomalies[i], processed_cti, mapping_mode)
                    result = {
                        "anomaly_id": uninterpreted_anomaly["id"],
                        "rule": uninterpreted_anomaly["description"],
                        "numResults": len(matches),
                        "results": matches
                    }
                    if "timestamp_format" in uninterpreted_anomaly.keys():
                        result["anomaly_timestamp"] = uninterpreted_anomaly["timestamp_format"]
                    else:
                        result["anomaly_timestamp"] = uninterpreted_anomaly["timestamp"]
                    output.append(result)
            case _:
                print('There is no such anomaly preprocessing option.')

        output_result_to_file(output)

if __name__ == '__main__':
    main()
