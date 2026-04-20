"""Tests for robots.txt and sitemap.xml parsing."""

from src.robots_sitemap import parse_robots_txt, parse_sitemap_xml


# ---------------------------------------------------------------------------
# robots.txt parsing
# ---------------------------------------------------------------------------

class TestParseRobotsTxt:
    def test_basic_disallow_and_sitemap(self):
        content = """\
User-agent: *
Disallow: /admin/
Disallow: /private/
Sitemap: https://example.com/sitemap.xml
"""
        result = parse_robots_txt(content)
        assert result.found is True
        assert "/admin/" in result.disallow_rules
        assert "/private/" in result.disallow_rules
        assert "https://example.com/sitemap.xml" in result.sitemap_urls

    def test_multiple_user_agents(self):
        content = """\
User-agent: Googlebot
Disallow: /nogoogle/

User-agent: *
Disallow: /secret/
Sitemap: https://example.com/sitemap.xml
"""
        result = parse_robots_txt(content)
        assert "/nogoogle/" in result.disallow_rules
        assert "/secret/" in result.disallow_rules

    def test_crawl_delay(self):
        content = """\
User-agent: *
Crawl-delay: 10
Disallow: /slow/
"""
        result = parse_robots_txt(content)
        assert result.crawl_delay == 10
        assert "/slow/" in result.disallow_rules

    def test_empty_content(self):
        result = parse_robots_txt("")
        assert result.found is False

    def test_whitespace_only(self):
        result = parse_robots_txt("   \n  \n  ")
        assert result.found is False

    def test_comments_ignored(self):
        content = """\
# This is a comment
User-agent: *
# Another comment
Disallow: /hidden/
"""
        result = parse_robots_txt(content)
        assert result.disallow_rules == ["/hidden/"]

    def test_raw_snippet_capped(self):
        content = "User-agent: *\nDisallow: /x\n" * 200
        result = parse_robots_txt(content)
        assert len(result.raw_snippet) <= 2000

    def test_no_disallow_rules(self):
        content = """\
User-agent: *
Allow: /
"""
        result = parse_robots_txt(content)
        assert result.found is True
        assert result.disallow_rules == []


# ---------------------------------------------------------------------------
# sitemap.xml parsing
# ---------------------------------------------------------------------------

class TestParseSitemapXml:
    def test_basic_sitemap(self):
        content = """\
<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url><loc>https://example.com/page1</loc></url>
  <url><loc>https://example.com/page2</loc></url>
  <url><loc>https://example.com/page3</loc></url>
</urlset>
"""
        result = parse_sitemap_xml(content)
        assert result.found is True
        assert result.url_count == 3
        assert "https://example.com/page1" in result.urls

    def test_sitemap_index(self):
        content = """\
<?xml version="1.0" encoding="UTF-8"?>
<sitemapindex xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <sitemap><loc>https://example.com/sitemap-posts.xml</loc></sitemap>
  <sitemap><loc>https://example.com/sitemap-pages.xml</loc></sitemap>
</sitemapindex>
"""
        result = parse_sitemap_xml(content)
        assert result.found is True
        assert len(result.nested_sitemaps) == 2
        assert "https://example.com/sitemap-posts.xml" in result.nested_sitemaps

    def test_caps_at_100(self):
        urls = "\n".join(
            f"  <url><loc>https://example.com/page{i}</loc></url>"
            for i in range(150)
        )
        content = f"""\
<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
{urls}
</urlset>
"""
        result = parse_sitemap_xml(content)
        assert len(result.urls) <= 100

    def test_malformed_xml(self):
        content = "<not valid xml <<>>"
        result = parse_sitemap_xml(content)
        assert result.found is True
        assert result.url_count == 0

    def test_empty_content(self):
        result = parse_sitemap_xml("")
        assert result.found is False

    def test_no_namespace(self):
        content = """\
<?xml version="1.0"?>
<urlset>
  <url><loc>https://example.com/no-ns</loc></url>
</urlset>
"""
        result = parse_sitemap_xml(content)
        assert result.url_count == 1
        assert "https://example.com/no-ns" in result.urls
