from html.parser import HTMLParser

class FormParser(HTMLParser):
        def __init__(self):
            super().__init__()
            self.forms = []
            self._in_form = False
            self._current = None

        def handle_starttag(self, tag, attrs):
            tag = tag.lower()
            attrs_dict = {k.lower(): v for k, v in attrs}
            if tag == "form":
                self._in_form = True
                self._current = {"attrs": attrs_dict, "inputs": [], "html": ""}
                # add opening form tag text
                attr_text = " ".join(f'{k}="{v}"' for k, v in attrs)
                self._current["html"] += f"<form {attr_text}>"
                return

            # Only process nested tags when we are inside a form and have a current buffer
            if self._in_form and self._current is not None:
                # capture input tags inside form
                if tag == "input":
                    self._current["inputs"].append(attrs_dict)
                # record any start tag inside form to keep a small snippet
                attr_text = " ".join(f'{k}="{v}"' for k, v in attrs)
                self._current["html"] += f"<{tag} {attr_text}>"

        def handle_endtag(self, tag):
            tag = tag.lower()
            if self._in_form and self._current is not None:
                self._current["html"] += f"</{tag}>"
            if tag == "form" and self._in_form:
                # finalize current form (only append if we have a buffer)
                if self._current is not None:
                    self.forms.append(self._current)
                self._current = None
                self._in_form = False

        def handle_data(self, data):
            if self._in_form and self._current is not None:
                self._current["html"] += data