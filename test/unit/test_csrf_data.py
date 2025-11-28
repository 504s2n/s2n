"""Reusable test data for CSRF plugin tests."""

HTML_WITH_CSRF_TOKEN = '''
<html>
  <body>
    <form action="/submit" method="post">
      <input type="hidden" name="csrf_token" value="abc123" />
      <input type="text" name="username" />
    </form>
  </body>
</html>
'''

HTML_WITHOUT_CSRF = '''
<html>
  <body>
    <form action="/login" method="post">
      <input type="text" name="username" />
      <input type="password" name="password" />
    </form>
  </body>
</html>
'''

HTML_NO_FORMS = '<html><head></head><body><p>No forms here</p></body></html>'
