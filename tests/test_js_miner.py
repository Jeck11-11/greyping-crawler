"""Tests for JavaScript bundle mining."""

from src.js_miner import (
    extract_endpoints,
    extract_internal_hosts,
    extract_script_urls,
    extract_sourcemap_url,
)


def test_extract_script_urls_resolves_relative_and_dedupes():
    html = """
    <html><head>
      <script src="/static/app.js"></script>
      <script src="https://cdn.example.com/lib.js"></script>
      <script src="/static/app.js"></script>
      <script src="data:text/javascript,foo"></script>
    </head></html>
    """
    urls = extract_script_urls(html, "https://example.com")
    assert "https://example.com/static/app.js" in urls
    assert "https://cdn.example.com/lib.js" in urls
    # deduped
    assert len(urls) == 2
    # data: URIs dropped
    assert all(not u.startswith("data:") for u in urls)


def test_extract_endpoints_finds_api_paths_and_base_urls():
    js = """
    const baseURL = "https://api.example.com";
    fetch("/api/v1/users");
    const gql = "/graphql/query?token=x";
    const apiUrl = 'https://internal-api.example.com/v2';
    """
    eps = extract_endpoints(js)
    assert "/api/v1/users" in eps
    assert "/graphql/query?token=x" in eps
    # both baseURL / apiUrl captures present
    assert any("api.example.com" in e for e in eps)
    assert any("internal-api.example.com" in e for e in eps)


def test_extract_internal_hosts_matches_internal_and_rfc1918():
    js = """
    const admin = "https://admin.internal/health";
    const dev   = "https://foo.corp:8080/";
    const ten   = "http://10.0.0.5/";
    const oneninetwo = "http://192.168.1.100/admin";
    """
    hosts = extract_internal_hosts(js)
    assert any("admin.internal" in h for h in hosts)
    assert any(".corp" in h for h in hosts)
    assert any("10.0.0.5" in h for h in hosts)
    assert any("192.168.1.100" in h for h in hosts)


def test_extract_sourcemap_url():
    js = "// some code\n//# sourceMappingURL=app.js.map\n"
    sm = extract_sourcemap_url(js, "https://example.com/static/app.js")
    assert sm == "https://example.com/static/app.js.map"


def test_extract_sourcemap_url_missing_returns_none():
    assert extract_sourcemap_url("console.log(1);", "https://x/y.js") is None
