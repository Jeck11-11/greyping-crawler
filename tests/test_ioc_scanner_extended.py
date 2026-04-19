"""Extended IoC scanner tests for new patterns."""

from src.ioc_scanner import scan_ioc


class TestTrustedIframes:
    def test_tiktok_iframe_trusted(self):
        html = '<iframe src="https://analytics.tiktok.com/pixel" width="0" height="0"></iframe>'
        findings = scan_ioc(html, "https://example.com")
        assert not any(f.ioc_type == "hidden_iframe" for f in findings)

    def test_tiktok_main_domain_trusted(self):
        html = '<iframe src="https://tiktok.com/embed/v2/12345" width="0" height="0"></iframe>'
        findings = scan_ioc(html, "https://example.com")
        assert not any(f.ioc_type == "hidden_iframe" for f in findings)

    def test_snapchat_iframe_trusted(self):
        html = '<iframe src="https://tr.snapchat.com/p" width="0" height="0"></iframe>'
        findings = scan_ioc(html, "https://example.com")
        assert not any(f.ioc_type == "hidden_iframe" for f in findings)

    def test_reddit_iframe_trusted(self):
        html = '<iframe src="https://embed.reddit.com/r/test/comments/abc" width="0" height="0"></iframe>'
        findings = scan_ioc(html, "https://example.com")
        assert not any(f.ioc_type == "hidden_iframe" for f in findings)


class TestWebAssemblyDetection:
    def test_detects_wasm_instantiate_with_atob(self):
        html = '<script>WebAssembly.instantiate(atob("AGFzbQE="));</script>'
        findings = scan_ioc(html, "https://example.com")
        assert any(f.ioc_type == "obfuscated_js" for f in findings)

    def test_detects_wasm_instantiate_with_uint8array(self):
        html = '<script>WebAssembly.instantiate(new Uint8Array([0,97]));</script>'
        findings = scan_ioc(html, "https://example.com")
        assert any(f.ioc_type == "obfuscated_js" for f in findings)


class TestSEOSpamKeywords:
    def test_detects_replica_watches(self):
        html = '<div style="display:none"><a href="https://spam.xyz">replica watches</a><a href="https://spam2.xyz">x</a><a href="https://spam3.xyz">y</a></div>'
        findings = scan_ioc(html, "https://example.com")
        assert any(f.ioc_type == "seo_spam" for f in findings)

    def test_detects_buy_followers(self):
        html = '<div style="visibility:hidden">buy followers now! cheap!</div>'
        findings = scan_ioc(html, "https://example.com")
        assert any(f.ioc_type == "seo_spam" for f in findings)
