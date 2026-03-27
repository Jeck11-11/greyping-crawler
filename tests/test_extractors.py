"""Tests for the extractor module."""

from bs4 import BeautifulSoup

from src.extractors import extract_contacts, extract_links, extract_page_metadata


def _soup(html: str) -> BeautifulSoup:
    return BeautifulSoup(html, "html.parser")


class TestExtractContacts:
    def test_extracts_emails_from_text(self):
        html = "<p>Contact us at info@example.com for details.</p>"
        contacts = extract_contacts(_soup(html), html)
        assert "info@example.com" in contacts.emails

    def test_extracts_mailto_links(self):
        html = '<a href="mailto:sales@example.com">Email Sales</a>'
        contacts = extract_contacts(_soup(html), html)
        assert "sales@example.com" in contacts.emails

    def test_skips_placeholder_emails(self):
        html = "<p>Use user@example.com as a template.</p>"
        contacts = extract_contacts(_soup(html), html)
        assert "user@example.com" not in contacts.emails

    def test_extracts_tel_links(self):
        html = '<a href="tel:+1-555-123-4567">Call us</a>'
        contacts = extract_contacts(_soup(html), html)
        assert len(contacts.phone_numbers) >= 1

    def test_extracts_phone_from_text(self):
        html = "<p>Call us at +1 (800) 555-1234 today!</p>"
        contacts = extract_contacts(_soup(html), html)
        assert len(contacts.phone_numbers) >= 1

    def test_extracts_social_profiles(self):
        html = """
        <a href="https://twitter.com/example">Twitter</a>
        <a href="https://www.linkedin.com/company/example">LinkedIn</a>
        <a href="https://github.com/example">GitHub</a>
        """
        contacts = extract_contacts(_soup(html), html)
        assert len(contacts.social_profiles) == 3

    def test_ignores_social_root_links(self):
        html = '<a href="https://twitter.com/">Twitter</a>'
        contacts = extract_contacts(_soup(html), html)
        assert len(contacts.social_profiles) == 0


class TestExtractLinks:
    def test_classifies_internal_links(self):
        html = '<a href="/about">About</a>'
        links = extract_links(_soup(html), "https://example.com/")
        assert len(links) == 1
        assert links[0].link_type == "internal"
        assert links[0].url == "https://example.com/about"

    def test_classifies_external_links(self):
        html = '<a href="https://other.com/page">Other</a>'
        links = extract_links(_soup(html), "https://example.com/")
        assert len(links) == 1
        assert links[0].link_type == "external"

    def test_skips_anchors_and_javascript(self):
        html = """
        <a href="#section">Jump</a>
        <a href="javascript:void(0)">Click</a>
        <a href="mailto:a@b.com">Mail</a>
        """
        links = extract_links(_soup(html), "https://example.com/")
        assert len(links) == 0

    def test_deduplicates_links(self):
        html = """
        <a href="/page">One</a>
        <a href="/page">Two</a>
        """
        links = extract_links(_soup(html), "https://example.com/")
        assert len(links) == 1

    def test_captures_anchor_text(self):
        html = '<a href="/products">Our Products</a>'
        links = extract_links(_soup(html), "https://example.com/")
        assert links[0].anchor_text == "Our Products"


class TestExtractPageMetadata:
    def test_extracts_title(self):
        html = "<html><head><title>My Page</title></head><body></body></html>"
        title, _, _ = extract_page_metadata(_soup(html))
        assert title == "My Page"

    def test_extracts_meta_description(self):
        html = '<html><head><meta name="description" content="A great page."></head></html>'
        _, desc, _ = extract_page_metadata(_soup(html))
        assert desc == "A great page."

    def test_extracts_content_snippet(self):
        html = "<html><body><p>Hello world, this is a test page.</p></body></html>"
        _, _, snippet = extract_page_metadata(_soup(html))
        assert "Hello world" in snippet

    def test_handles_missing_metadata(self):
        html = "<html><body><p>Content only.</p></body></html>"
        title, desc, snippet = extract_page_metadata(_soup(html))
        assert title == ""
        assert desc == ""
        assert "Content only." in snippet
