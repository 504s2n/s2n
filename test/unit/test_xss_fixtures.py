"""테스트에서 사용할 데이터 상수"""

SAMPLE_PAYLOADS = [
    "<script>alert(1)</script>",
    "\"'><img src=x onerror=alert(1)>",
    "<svg onload=alert(1)>",
]

SAMPLE_PAYLOADS_JSON = {
    "payloads": {
        "basic": ["<script>alert(1)</script>"],
        "attribute": ["\" onload=alert(1) \""]
    },
    "filter_bypass": ["<img src=x onerror=alert(1)>"],
    "korean_encoding_specific": {
        "euc-kr": ["테스트<script>"]
    }
}

SIMPLE_HTML = "<html><body>ok</body></html>"

FORM_WITH_CSRF_HTML = """
<form action="/submit" method="POST">
  <input type="hidden" name="csrf_token" value="abc123">
  <input type="text" name="comment">
  <input type="submit" name="btnSubmit" value="Submit">
</form>
"""

FORM_WITH_MULTIPLE_INPUTS_HTML = """
<form action="/login" method="POST">
  <input type="text" name="username" value="">
  <input type="password" name="password" value="">
  <input type="hidden" name="nonce" value="xyz789">
  <input type="submit" value="Login">
</form>
"""

COOKIE_HEADER = "session_id=abc123; user=test"
