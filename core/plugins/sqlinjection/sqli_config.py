# --- SQLi 스캐너 설정 ---
TEST_PAYLOAD = "'"
TEST_PAYLOAD_TIME_BLIND = "' AND (SELECT 5=5 FROM (SELECT(SLEEP(5)))a) AND '1'='1"
TIME_THRESHOLD = 4.5

# SQLi 성공 (데이터 노출) 징후
SUCCESS_INDICATORS = [
    "ID: 1", "1, admin", "user"
]

# SQL 에러 기반 탐지를 위한 핵심 에러 키워드
ERROR_INDICATORS = [
    "unclosed quotation mark",
    "you have an error in your sql syntax",
    "database error",
    "error in your query",
    "mysql_fetch_array()",
    "unknown column",
    "error converting data type"
]