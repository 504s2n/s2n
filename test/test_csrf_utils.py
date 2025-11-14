from s2n.s2nscanner.plugins.csrf.csrf_utils import FormParser
from s2n.s2nscanner.plugins.csrf.test.test_data import HTML_WITH_CSRF_TOKEN, HTML_WITHOUT_CSRF


def test_formparser_parses_forms_and_inputs():
    parser = FormParser()
    parser.feed(HTML_WITH_CSRF_TOKEN)
    forms = parser.forms
    assert isinstance(forms, list)
    assert len(forms) == 1
    form = forms[0]
    assert "inputs" in form
    inputs = form["inputs"]
    # should contain at least the csrf hidden input and username
    names = [i.get("name", "") for i in inputs]
    assert "csrf_token" in names or any("csrf" in n for n in names)


def test_formparser_handles_no_forms():
    parser = FormParser()
    parser.feed(HTML_WITHOUT_CSRF)
    forms = parser.forms
    assert isinstance(forms, list)
    assert len(forms) == 1
    form = forms[0]
    inputs = form["inputs"]
    # should not find hidden csrf input
    assert not any(i.get("type", "").lower() == "hidden" for i in inputs)
