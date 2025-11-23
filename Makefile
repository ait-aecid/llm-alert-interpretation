.PHONY:clean
clean:
	rm -rf index_dir
	rm -f outputs/matches.json

.PHONY:match_fulltext_aminer_simple
match_fulltext_aminer_simple: clean
	python3 main.py -AS test_data/just_a_test_anomaly.json -AC test_data/aminer_anomaly_config.json -AP fulltext -CS "test_data/just_a_test_cti.json" -CP fulltext -MM fulltext

.PHONY:match_fulltext_aminer_all
match_fulltext_aminer_all: clean
	python3 main.py -AS test_data/just_a_test_anomaly.json -AC test_data/aminer_anomaly_config.json -AP fulltext -CS "test_data/generated.json, test_data/real.json, test_data/TaranisReports/2024-05-13.json, test_data/TaranisReports/2024-05-14.json, test_data/TaranisReports/2024-05-15.json, test_data/TaranisReports/2024-05-16.json, test_data/TaranisReports/2024-05-17.json, test_data/TaranisReports/2024-05-18.json, test_data/TaranisReports/2024-05-19.json, test_data/TaranisReports/2024-05-20.json, test_data/TaranisReports/2024-05-21.json, test_data/TaranisReports/2024-05-22.json, test_data/TaranisReports/2024-05-23.json, test_data/TaranisReports/2024-05-24.json" -CP fulltextEntityIOC -MM fulltext

.PHONY:match_attackg_mitre_aminer_simple
match_attackg_mitre_aminer_simple : clean
	python3 main.py -AS test_data/aminer_attack_lines_short.json -AC test_data/aminer_anomaly_config.json -AP chatgpt -CS "test_data/just_a_test_cti.json" -CP attackg_mitre -MM mitre

.PHONY:match_attackg_graph_aminer_simple
match_attackg_mitre_aminer_simple : clean
	python3 main.py -AS test_data/aminer_attack_lines_short.json -AC test_data/aminer_anomaly_config.json -AP chatgpt -CS "test_data/just_a_test_cti.json" -CP attackg_mitre -MM mitre

.PHONY:match_attackg_mitre_gemini_aminer_no_attack
match_attackg_mitre_gemini_aminer_no_attack : clean
	python3 main.py -AS test_data/aminer_no_attack_lines.json -AC test_data/aminer_anomaly_config.json -AP gemini -CS "test_data/just_a_test_cti.json" -CP attackg_mitre -MM mitre

.PHONY:match_attackg_mitre_gemini_aminer_attacks
match_attackg_mitre_gemini_aminer_attacks : clean
	python3 main.py -AS test_data/aminer_attack_lines.json -AC test_data/aminer_anomaly_config.json -AP gemini -CS "test_data/just_a_test_cti.json" -CP attackg_mitre -MM mitre

.PHONY:match_attackg_mitre_chatgpt_aminer_no_attack
match_attackg_mitre_chatgpt_aminer_no_attack : clean
	python3 main.py -AS test_data/aminer_no_attack_lines.json -AC test_data/aminer_anomaly_config.json -AP chatgpt -CS "test_data/just_a_test_cti.json" -CP attackg_mitre -MM mitre

.PHONY:match_attackg_mitre_chatgpt_aminer_attacks
match_attackg_mitre_chatgpt_aminer_attacks : clean
	python3 main.py -AS test_data/aminer_attack_lines.json -AC test_data/aminer_anomaly_config.json -AP chatgpt -CS "test_data/just_a_test_cti.json" -CP attackg_mitre -MM mitre
