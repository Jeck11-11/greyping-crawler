"""Extended pattern tests for the secret scanner."""

from src.secret_scanner import scan_secrets

# Build test keys dynamically so GitHub push protection does not flag them.
_AWS_AKIA = "AKIA" + "IOSFODNN7EXAMPLE"
_AWS_ASIA = "ASIA" + "IOSFODNN7EXAMPLE"
_SLACK_BOT = "xoxb-" + "1234567890" + "-" + "1234567890" + "-" + "AbCdEfGhIjKlMnOpQrStUvWx"
_TWILIO_SID = "AC" + "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4"


class TestAWSPatterns:
    def test_detects_akia_prefix(self):
        html = f'<script>var key = "{_AWS_AKIA}";</script>'
        findings = scan_secrets(html)
        assert any(f.secret_type == "aws_access_key" for f in findings)

    def test_detects_asia_prefix(self):
        html = f'<script>var key = "{_AWS_ASIA}";</script>'
        findings = scan_secrets(html)
        assert any(f.secret_type == "aws_access_key" for f in findings)

    def test_rejects_wrong_prefix(self):
        html = '<script>var key = "AKZZ1234567890123456";</script>'
        findings = scan_secrets(html)
        assert not any(f.secret_type == "aws_access_key" for f in findings)


class TestSlackBotToken:
    def test_detects_xoxb_token(self):
        html = f'<script>var token = "{_SLACK_BOT}";</script>'
        findings = scan_secrets(html)
        assert any(f.secret_type == "slack_token" for f in findings)


class TestTwilioSID:
    def test_detects_twilio_account_sid(self):
        html = f'<script>var sid = "{_TWILIO_SID}";</script>'
        findings = scan_secrets(html)
        assert any(f.secret_type == "twilio_credential" for f in findings)

    def test_rejects_short_sid(self):
        html = '<script>var sid = "ACa1b2c3d4";</script>'
        findings = scan_secrets(html)
        assert not any(f.secret_type == "twilio_credential" for f in findings)


class TestDatabaseURL:
    def test_detects_postgres_with_credentials(self):
        html = '<!-- postgres://admin:secret@db.example.com:5432/mydb -->'
        findings = scan_secrets(html)
        assert any(f.secret_type == "database_credential" for f in findings)

    def test_rejects_postgres_without_credentials(self):
        html = '<!-- postgres://db.example.com:5432/mydb -->'
        findings = scan_secrets(html)
        assert not any(f.secret_type == "database_credential" for f in findings)


class TestStripeKey:
    def test_detects_bounded_stripe_key(self):
        key = "sk_live_" + "a" * 24
        html = f'<script>Stripe("{key}");</script>'
        findings = scan_secrets(html)
        assert any(f.secret_type == "stripe_key" for f in findings)


class TestFalsePositives:
    def test_clean_html_no_findings(self):
        html = """
        <html>
        <head><title>My Site</title></head>
        <body>
            <h1>Welcome</h1>
            <p>Contact us at hello@example.com</p>
            <div class="container" id="main-content">
                <img src="/images/logo.png" alt="Logo">
            </div>
        </body>
        </html>
        """
        findings = scan_secrets(html)
        assert len(findings) == 0
