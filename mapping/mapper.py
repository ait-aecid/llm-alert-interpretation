from whoosh.qparser import QueryParser, MultifieldParser
from whoosh.index import open_dir

from mapping.mode import MappingMode

class Mapper:
    mapping_mode = None

    def __init__(self, mapping_mode=None):
        self.mapping_mode = mapping_mode 

    def _full_text_mapping(self, anomaly):
        output = []

        # Define search fields from CTI information
        #field_boosts = {'content': 3.0, 'title': 1.0, 'author': 0.5}

        search = ""

        for key, value in anomaly.items():
            if type(value) is list:
                for element in value:
                    if len(search) > 0:
                        search += " OR '" + element + "'"
                    else: 
                        search += "'" + element + "'"
            else:
                if len(search) > 0:
                    search += " OR '" + value + "'"
                else:
                    search += "'" + value + "'"
        
        ix = open_dir("index_dir")
        query = QueryParser("content", schema=ix.schema).parse(search)
        #query = MultifieldParser(field_boosts.keys(), schema=ix.schema, fieldboosts=field_boosts).parse(search)

        with ix.searcher() as searcher:
            
            # add filter for date range here?
            # like this:
                # Filter documents older than 7 days
                #old_q = query.DateRange("created", None, datetime.now() - timedelta(days=7))

            results = searcher.search(query, limit=10, terms=True)

            output = {}
            output["anomaly_id"] = anomaly["id"]
            if "timestamp_format" in anomaly.keys():
                output["anomaly_timestamp"] = anomaly["timestamp_format"]
            else:
                output["anomaly_timestamp"] = anomaly["timestamp"]
            output["rule"] = anomaly["description"]
            result_list = []
            for result in results:
                matched = []
                for match in result.matched_terms():
                    matched.append((match[0], match[1].decode("utf-8")))
                result_element = {
                    "title": result["title"],
                    "source": result["link"],
                    "date": result["published"],
                    "content": result["initial_content"],
                    "score": result.score,
                    "matched_terms": matched
                }    
                result_list.append(result_element)
            output["numResults"] = len(result_list)
            output["results"] = result_list
            return output

    def _graph_alignment(self, anomaly, cti):
        pass

    def _mitre_mapping(self, anomaly, cti):
        matches = []
        anomaly_ids = [id.split('.')[0] for id in anomaly['mitre']]
        set_anomaly = set(anomaly_ids)

        cti_lists = []
        for element in cti[0]:
            cti_ids = [id for id in element['extracted']]
            cti_lists.append(cti_ids)

        for j, cti_sublist in enumerate(cti_lists):
            set_cti = set(cti_sublist)

            intersection = set_anomaly & set_cti
            union = set_anomaly | set_cti
            jaccard = len(intersection) / len(union) if union else 0

            if jaccard >= 0.1:
                report = cti[0][j]
                matches.append({
                    "title": report["title"],
                    "source": report["source"],
                    "date": report["date"],
                    "content": report["content"],
                    'score': round(jaccard, 3),
                    'matched_ids': list(intersection)
                })

        # Sort matches by Jaccard score, descending
        matches.sort(key=lambda x: -x['score'])
        return matches

    def find_mappings(self, anomaly, cti): 
        match (self.mapping_mode):
            case MappingMode.FULL_TEXT:
                return self._full_text_mapping(anomaly)
            case MappingMode.GRAPH_ALIGNMENT:
                return self._graph_alignment(anomaly, cti)
            case MappingMode.ATTACK_MAPPING:
                return self._mitre_mapping(anomaly, cti)
            case _:
                return []


