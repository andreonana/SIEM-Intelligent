 .env.example                                       |  33 [31m-----[m
 backend/app/api/v1/routers/logs.py                 | 123 [31m------------------[m
 backend/app/core/config.py                         |  37 [31m------[m
 .../parsers/__init__.py => db/elasticsearch.py}    |   0
 backend/app/db/elasticsearch_client.py             |  97 [31m---------------[m
 backend/app/main.py                                |  90 [31m--------------[m
 backend/app/modules/ingestion/service.py           | 128 [31m-------------------[m
 backend/app/modules/normalisation/parsers/base.py  |  61 [31m---------[m
 .../modules/normalisation/parsers/json_parser.py   |  54 [31m--------[m
 .../app/modules/normalisation/parsers/registry.py  |  41 [31m------[m
 .../modules/normalisation/parsers/syslog_parser.py |  94 [31m--------------[m
 backend/app/modules/normalisation/service.py       |  72 [31m-----------[m
 backend/app/modules/normalisation/tagging.py       |  63 [31m----------[m
 backend/app/modules/rbac/local_protection.py       |  88 [31m-------------[m
 backend/app/schemas/log.py                         |  90 [31m--------------[m
 backend/auth.py                                    | 111 [31m-----------------[m
 backend/requirements.txt                           |   7 [31m--[m
 backend/retention.py                               | 118 [31m------------------[m
 backend/roles.py                                   |  84 [31m-------------[m
 docs/schemas-bdd/erd.md => dataset/app/__init__.py |   0
 .../app/db/__init__.py                             |   0
 dataset/app/db/elasticsearch_client.py             |  33 [32m+++++[m
 dataset/app/db/init_indices.py                     | 135 [32m++++++++++++++++++++[m
 dataset/requirements.txt                           |   4 [32m+[m
 dataset/scripts/generate_test_logs.py              | 122 [32m++++++++++++++++++[m
 dataset/scripts/ingest_test_logs.py                |  60 [32m+++++++++[m
 dataset/scripts/validate_ingestion.py              | 125 [32m+++++++++++++++++++[m
 .../tests/__init__.py                              |   0
 dataset/tests/conftest.py                          |   5 [32m+[m
 dataset/tests/test_indexing_performance.py         |  93 [32m++++++++++++++[m
 dataset/tests/test_ingestion_edge_cases.py         | 138 [32m+++++++++++++++++++++[m
 docs/schemas-bdd/SCHEMA_BDD.png                    | Bin [31m0[m -> [32m65879[m bytes
 docs/schemas-bdd/schema-bdd.md                     |  74 [32m+++++++++++[m
 33 files changed, 789 insertions(+), 1391 deletions(-)
