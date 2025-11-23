import json
import os
import re
import copy
import subprocess

from whoosh.fields import Schema, TEXT, ID
from whoosh.index import create_in, open_dir
from whoosh.qparser import QueryParser

from tqdm import tqdm

from cti_preprocessing.mode import CTIProcessingMode

class CTIProcessor:
    processing_mode = None

    def __init__(self, processing_mode=None):
        self.processing_mode = processing_mode

    def _ioc_extraction(self, report):
        with open("./preprocessing_files/ioc_patterns.json") as pattern_file:
            ioc_regexPattern = json.load(pattern_file)

            for data_item in report:
                for news_item in data_item['news_items']:
                    new_content = ""

                    found_items = []
                    # Find IoC items in the content field of the report object
                    for _, regex_options in ioc_regexPattern.items():
                        for regex in regex_options:
                            match_iter = re.finditer(regex, news_item['content']) # iterator over all non-overlapping matches in string
                            for match in match_iter:
                                found_items.append((match.group(), match.span()[0], match.span()[1]))

                    # Check for overlaps, if one exists -> keep longest
                    overlap_free_ioc_items = []
                    if len(found_items) > 0:

                        found_items.sort(key=lambda x: x[1])
                        last = found_items[0][2]
                        overlap_free_ioc_items.append(found_items[0][0])

                        for i in range(1, len(found_items)):
                            if last <= found_items[i][1]:
                                overlap_free_ioc_items.append(found_items[i][0])
                                last = found_items[i][2]

                    for item in overlap_free_ioc_items:
                        new_content += item + " "

                    news_item['content'] = new_content[:-1] # remove last space

            return report

    def _entity_extraction(self, report):
        apts_file = open("./preprocessing_files/apts.json")
        apts = json.load(apts_file)
        apts_file.close()

        countries_en_file = open("./preprocessing_files/countries.json")
        countries = json.load(countries_en_file)
        countries_en_file.close()

        countries_de_file = open("./preprocessing_files/countries_de.json")
        countries_de = json.load(countries_de_file)
        countries_de_file.close()

        cyber_file = open("./preprocessing_files/cyber.json")
        cybers = json.load(cyber_file)
        cyber_file.close()

        products_file = open("./preprocessing_files/products.json")
        products = json.load(products_file)
        products_file.close()

        vendors_file = open("./preprocessing_files/vendors.json")
        vendors = json.load(vendors_file)
        vendors_file.close()

        for data_item in report:
            for news_item in data_item['news_items']:
                # Find well-known entities in the content field of the report object
                new_content = ""
                for apt in apts:
                    if apt.lower() in news_item['content'].lower():
                        new_content += apt + " "

                for country in countries:
                    if country.lower() in news_item['content'].lower():
                        new_content += country + " "

                for country in countries_de: # German version of country names
                    if country.lower() in news_item['content'].lower():
                        new_content += country + " "

                for cyber in cybers:
                    if cyber.lower() in news_item['content'].lower():
                        new_content += cyber + " "

                for product in products:
                    if product.lower() in news_item['content'].lower():
                        new_content += product + " "

                for vendor in vendors:
                    if vendor.lower() in news_item['content'].lower():
                        new_content += vendor + " "

                news_item['content'] = new_content[:-1] # remove last space

        return report

    def _full_text_processing(self, report, initial_report=None):
        schema = Schema(
            id=ID(stored=True),
            title=TEXT(stored=True),
            content=TEXT(stored=True),
            initial_content=ID(stored=True),
            author=TEXT(stored=True),
            link=ID(stored=True),
            published=ID(stored=True)
        )

        index_dir = "index_dir"
        check_for_duplicates = False
        if not os.path.exists(index_dir):
            os.mkdir(index_dir)
            ix = create_in(index_dir, schema)
        else:
            ix = open_dir(index_dir)
            check_for_duplicates = True

        writer = ix.writer()

        with ix.searcher() as searcher:
            # search first item in report if the first item is inside the report it will be the same report
            data_counter = 0
            for data_item in tqdm(report):
                if check_for_duplicates:
                    query = QueryParser('title', ix.schema).parse(data_item['news_items'][0]['title'])
                    if len(searcher.search(query)) > 0:
                        data_counter += 1
                        continue

                news_counter = 0
                for news_item in data_item['news_items']:
                    if initial_report:
                        writer.add_document(
                            title=news_item['title'],
                            link=news_item['link'],
                            published=news_item['published'],
                            content=news_item['content'],
                            initial_content=initial_report[data_counter]['news_items'][news_counter]['content'],
                            author=news_item['author']
                        )
                    else:
                        writer.add_document(
                            title=news_item['title'],
                            link=news_item['link'],
                            published=news_item['published'],
                            content=news_item['content'],
                            initial_content=news_item['content'],
                            author=news_item['author']
                        )
                    news_counter += 1
                data_counter += 1

        writer.commit()
        return writer

    def _attacKG_graph(self, report):
        os.system("python ")

    def _attacKG_mitre(self, report):
        if os.path.exists('./preprocessing_files/attackg_mitre.json'):
            with open('./preprocessing_files/attackg_mitre.json') as file:
                return json.load(file)

        working_reports = json.load(report)

        documents = []
        for r in working_reports:
            for item in r['news_items']:
                documents.append((item['title'] + "\n" + item['content'], item['title'], item['link'], item['published'], item['content']))

        results = []
        os.chdir("./cti_preprocessing/AttacKG/")
        for doc in documents:
            with open("document.txt", "w") as f:
                f.write(doc[0])

            args = [
                './attack_venv/bin/python', 'main.py',
                '-M', 'techniqueIdentification',
                '-T', './templates',
                '-R', 'document.txt',
                '-O', './output'
            ]

            subprocess.run(args, stderr=subprocess.DEVNULL)
            with open('output_techniques.json', 'r') as file:
                data = json.load(file)

                result_element = {
                    "title": doc[1],
                    "source": doc[2],
                    "date": doc[3],
                    "content": doc[4],
                    "extracted": data
                }
                results.append(result_element)

        os.chdir("./../..")
        with open("./preprocessing_files/attackg_mitre.json", "w") as f:
            json.dump(results, f, indent=2)

        return results


    def report_to_intermediate(self, report):
        match (self.processing_mode):
            case CTIProcessingMode.FULL_TEXT:
                report = json.load(report)
                return self._full_text_processing(report)
            case CTIProcessingMode.ATTACKG_GRAPH:
                return self._attacKG_graph(report)
            case CTIProcessingMode.ATTACKG_MITRE:
                return self._attacKG_mitre(report)
            case CTIProcessingMode.FULL_TEXT_WITH_ENTITY_IOC_EXTR:
                working_report = json.load(report)
                working_report2 = copy.deepcopy(working_report)
                initial_report = copy.deepcopy(working_report)
                ioc_processed_report = self._ioc_extraction(working_report)
                entity_processed_report = self._entity_extraction(working_report2)

                for i in range(0, len(ioc_processed_report)):
                    for j in range(0, len(ioc_processed_report[i]['news_items'])):
                        ioc_processed_report[i].get('news_items')[j]['content'] += " " + entity_processed_report[i].get('news_items')[j]['content']

                return self._full_text_processing(ioc_processed_report, initial_report)
            case _:
                return report
