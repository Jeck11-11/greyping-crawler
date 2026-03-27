"""Tests for the secret scanner module."""

from src.secret_scanner import scan_secrets

# Build test keys dynamically so GitHub push protection does not flag them.
_STRIPE_SK_PREFIX = "sk_live_"
_STRIPE_SK_SUFFIX = "abcdefghijklmnopqrstuvwx"
_STRIPE_SK = _STRIPE_SK_PREFIX + _STRIPE_SK_SUFFIX


class TestScanSecrets:
    def test_detects_aws_access_key(self):
        html = '<script>var key = "AKIAIOSFODNN7EXAMPLE";</script>'
        findings = scan_secrets(html)
        assert any(f.secret_type == "aws_access_key" for f in findings)

    def test_detects_google_api_key(self):
        html = '<meta name="api" content="AIzaSyA1234567890abcdefghijklmnopqrstuv">'
        findings = scan_secrets(html)
        assert any(f.secret_type == "google_api_key" for f in findings)

    def test_detects_github_token(self):
        html = "<!-- token: ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij -->"
        findings = scan_secrets(html)
        assert any(f.secret_type == "github_token" for f in findings)

    def test_detects_stripe_key(self):
        html = f'<script>Stripe("{_STRIPE_SK}");</script>'
        findings = scan_secrets(html)
        assert any(f.secret_type == "stripe_key" for f in findings)

    def test_detects_generic_password(self):
        html = '<script>var password = "SuperSecret123!";</script>'
        findings = scan_secrets(html)
        assert any(f.secret_type == "generic_password" for f in findings)

    def test_detects_database_url(self):
        html = '<!-- postgres://admin:secret@db.example.com:5432/mydb -->'
        findings = scan_secrets(html)
        assert any(f.secret_type == "database_credential" for f in findings)

    def test_detects_private_key(self):
        html = "<pre>-----BEGIN RSA PRIVATE KEY-----\nMIIEow...</pre>"
        findings = scan_secrets(html)
        assert any(f.secret_type == "private_key" for f in findings)

    def test_detects_jwt_token(self):
        html = '<script>var token = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U";</script>'
        findings = scan_secrets(html)
        assert any(f.secret_type == "jwt_token" for f in findings)

    def test_detects_slack_webhook(self):
        html = 'var url = "https://hooks.slack.com/services/T0000000/B0000000/XXXXXXXXXXXXXXXX";'
        findings = scan_secrets(html)
        assert any(f.secret_type == "slack_webhook" for f in findings)

    def test_no_false_positives_on_clean_html(self):
        html = "<html><body><h1>Hello World</h1><p>This is a normal page.</p></body></html>"
        findings = scan_secrets(html)
        assert len(findings) == 0

    def test_redacts_values(self):
        html = '<script>var key = "AKIAIOSFODNN7EXAMPLE";</script>'
        findings = scan_secrets(html)
        for f in findings:
            # The full value should NOT appear in the preview
            assert "AKIAIOSFODNN7EXAMPLE" not in f.value_preview
            assert "..." in f.value_preview

    def test_deduplicates_same_secret(self):
        html = '<script>var a = "AKIAIOSFODNN7EXAMPLE"; var b = "AKIAIOSFODNN7EXAMPLE";</script>'
        findings = scan_secrets(html)
        aws_findings = [f for f in findings if f.secret_type == "aws_access_key"]
        assert len(aws_findings) == 1

    def test_classifies_location_script(self):
        html = '<html><script>var password = "MySecret123!";</script></html>'
        findings = scan_secrets(html)
        pwd_findings = [f for f in findings if f.secret_type == "generic_password"]
        assert any(f.location == "script" for f in pwd_findings)

    def test_classifies_location_comment(self):
        html = f'<!-- api_key = "{_STRIPE_SK}" -->'
        findings = scan_secrets(html)
        assert any(f.location == "html_comment" for f in findings)
