from __future__ import annotations

from html.parser import HTMLParser
import re
from urllib.parse import urljoin, urlsplit

from ..scanner.findings import make_finding


class PageParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.links: list[str] = []
        self.forms: list[dict] = []
        self._form: dict | None = None
        self._password = False
        self.resources: list[str] = []
        self.source_maps: list[str] = []
    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag in {"a", "link"} and a.get("href"):
            self.links.append(a["href"])
        if tag == "link" and a.get("href") and "stylesheet" in (a.get("rel") or "").lower():
            self.resources.append(a["href"])
        if tag in {"script", "img", "iframe", "source", "video", "audio"}:
            src = a.get("src") or a.get("data")
            if src: self.resources.append(src)
        if tag == "form":
            self._form = {"action": a.get("action", ""), "method": (a.get("method") or "get").lower(), "has_password": False}
        if tag == "input" and self._form is not None and (a.get("type") or "text").lower() == "password":
            self._form["has_password"] = True
    def handle_endtag(self, tag):
        if tag == "form" and self._form is not None:
            self.forms.append(self._form)
            self._form = None
    def handle_comment(self, data):
        marker = "sourceMappingURL="
        if marker in data:
            self.source_maps.append(data.split(marker, 1)[1].strip().split()[0][:300])


def inspect_html(url: str, body: str, *, is_https: bool) -> tuple[list[dict], list[str]]:
    parser = PageParser()
    try: parser.feed(body[:1_000_000])
    except Exception: pass
    findings: list[dict] = []
    for resource in parser.resources:
        if is_https and resource.strip().lower().startswith("http://"):
            findings.append(make_finding(title="Potential mixed-content resource", category="mixed-content", severity="medium",
                confidence="high", url=url, description="An HTTPS page references a resource using HTTP. Browsers may block it or load it insecurely depending on resource type.",
                evidence={"resource_url": resource[:300]}, remediation="Serve the resource over HTTPS and update the reference."))
    for form in parser.forms:
        action = form.get("action", "")
        resolved = urljoin(url, action) if action else url
        scheme = urlsplit(resolved).scheme.lower()
        if form.get("has_password") and scheme == "http":
            findings.append(make_finding(title="Password form submits over HTTP", category="forms", severity="high", confidence="high",
                url=url, description="A form containing a password field appears to submit to an HTTP URL, which does not provide transport encryption.",
                evidence={"form_action_scheme": "http", "method": form.get("method", "get")},
                remediation="Serve the form and its destination exclusively over HTTPS, and avoid putting secrets in query strings."))
        elif form.get("has_password") and urlsplit(resolved).netloc != urlsplit(url).netloc:
            findings.append(make_finding(title="Password form targets a different origin", category="forms", severity="info", confidence="medium",
                url=url, description="A form with a password field targets a different origin. This can be intentional, but should be reviewed.",
                evidence={"destination_origin": f"{urlsplit(resolved).scheme}://{urlsplit(resolved).netloc}"},
                remediation="Verify that the destination is controlled by the expected service and uses HTTPS."))
    source_map_refs = list(parser.source_maps)
    # JavaScript source-map comments can occur inside script data rather than HTML comments.
    source_map_refs.extend(re.findall(r"sourceMappingURL\s*=\s*([^\s*]+)", body[:1_000_000])[:10])
    for source_map in source_map_refs:
        if source_map and not source_map.startswith("data:"):
            findings.append(make_finding(title="Source-map reference is exposed in page markup", category="information-disclosure", severity="info",
                confidence="medium", url=url, description="The markup includes a source-map reference. Source maps are not automatically a vulnerability, but may expose original source context if publicly accessible.",
                evidence={"source_map_reference": source_map[:200]}, remediation="Review whether the referenced source map is intended for public use."))
    urls = []
    for href in parser.links:
        if href.startswith(("#", "javascript:", "mailto:", "tel:", "data:")):
            continue
        abs_url = urljoin(url, href)
        if urlsplit(abs_url).scheme in {"http", "https"}:
            urls.append(abs_url)
    return findings, urls
