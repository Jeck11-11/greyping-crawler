"""Typosquatting / brand impersonation detection via domain permutations."""

from __future__ import annotations

import asyncio
import logging
import time

import dns.resolver

from .models import TyposquatCandidate, TyposquattingResult

logger = logging.getLogger(__name__)

# Visually similar character substitutions
_HOMOGLYPHS: dict[str, list[str]] = {
    "a": ["4", "à", "á", "â", "ã", "ä", "å", "ɑ"],
    "b": ["d", "6"],
    "c": ["k", "ç"],
    "d": ["b", "cl"],
    "e": ["3", "è", "é", "ê", "ë"],
    "g": ["q", "9"],
    "h": ["b"],
    "i": ["1", "l", "!", "í", "ì"],
    "k": ["c"],
    "l": ["1", "i", "|"],
    "m": ["rn", "nn"],
    "n": ["m", "r"],
    "o": ["0", "ö", "ò", "ó"],
    "p": ["q"],
    "q": ["g", "p"],
    "r": ["n"],
    "s": ["5", "$", "z"],
    "t": ["7"],
    "u": ["v", "ü", "ù", "ú"],
    "v": ["u", "w"],
    "w": ["vv", "uu"],
    "y": ["ÿ"],
    "z": ["s", "2"],
}

# QWERTY adjacent-key map
_QWERTY_ADJACENT: dict[str, str] = {
    "a": "qwsz", "b": "vghn", "c": "xdfv", "d": "erfcxs",
    "e": "wrsdf", "f": "rtgvcd", "g": "tyhbvf", "h": "yujnbg",
    "i": "uojkl", "j": "uikhng", "k": "iolmjh", "l": "opkj",
    "m": "njk", "n": "bhjm", "o": "iplk", "p": "ol",
    "q": "wa", "r": "edft", "s": "wedxza", "t": "rfgy",
    "u": "yhjik", "v": "cfgb", "w": "qase", "x": "zsdc",
    "y": "tghu", "z": "asx",
}

_COMMON_TLDS = ["com", "net", "org", "io", "co", "app", "xyz", "info", "biz", "dev"]


def _split_domain(domain: str) -> tuple[str, str]:
    """Split domain into (name, tld). E.g. 'greyping.com' -> ('greyping', 'com')."""
    parts = domain.rsplit(".", 1)
    if len(parts) == 2:
        return parts[0], parts[1]
    return domain, ""


def _similarity(original: str, candidate: str) -> float:
    """Simple ratio of matching chars to max length."""
    if not original or not candidate:
        return 0.0
    max_len = max(len(original), len(candidate))
    matches = sum(1 for a, b in zip(original, candidate) if a == b)
    return round(matches / max_len, 2)


def generate_typo_candidates(domain: str) -> list[dict[str, str]]:
    """Generate domain permutations. Returns list of {domain, technique}."""
    name, tld = _split_domain(domain.lower().strip())
    if not name or not tld:
        return []

    seen: set[str] = {domain.lower()}
    candidates: list[dict[str, str]] = []

    def _add(candidate_name: str, technique: str) -> None:
        full = f"{candidate_name}.{tld}"
        if full not in seen and candidate_name and len(candidate_name) > 1:
            seen.add(full)
            candidates.append({"domain": full, "technique": technique})

    # Character omission
    for i in range(len(name)):
        _add(name[:i] + name[i + 1:], "omission")

    # Character duplication
    for i in range(len(name)):
        _add(name[:i] + name[i] + name[i:], "duplication")

    # Character transposition
    for i in range(len(name) - 1):
        swapped = list(name)
        swapped[i], swapped[i + 1] = swapped[i + 1], swapped[i]
        _add("".join(swapped), "transposition")

    # Homoglyph substitution
    for i, ch in enumerate(name):
        for replacement in _HOMOGLYPHS.get(ch, []):
            _add(name[:i] + replacement + name[i + 1:], "homoglyph")

    # Adjacent-key substitution
    for i, ch in enumerate(name):
        for adj in _QWERTY_ADJACENT.get(ch, ""):
            _add(name[:i] + adj + name[i + 1:], "keyboard")

    # TLD variation
    for alt_tld in _COMMON_TLDS:
        if alt_tld != tld:
            full = f"{name}.{alt_tld}"
            if full not in seen:
                seen.add(full)
                candidates.append({"domain": full, "technique": "tld_swap"})

    return candidates


async def check_typosquatting(
    domain: str,
    *,
    timeout: int = 30,
    concurrency: int = 50,
) -> TyposquattingResult:
    """Generate typo candidates and check which ones resolve in DNS."""
    t0 = time.monotonic()
    candidates = generate_typo_candidates(domain)
    if not candidates:
        return TyposquattingResult(domain=domain)

    original_name, _ = _split_domain(domain.lower())
    sem = asyncio.Semaphore(concurrency)
    resolver = dns.resolver.Resolver()
    resolver.lifetime = min(timeout, 5)
    resolver.timeout = min(timeout, 5)

    async def _resolve(entry: dict[str, str]) -> TyposquatCandidate | None:
        async with sem:
            try:
                loop = asyncio.get_running_loop()
                answers = await loop.run_in_executor(
                    None, lambda: resolver.resolve(entry["domain"], "A"),
                )
                a_records = [str(r) for r in answers]
                if a_records:
                    cand_name, _ = _split_domain(entry["domain"])
                    return TyposquatCandidate(
                        domain=entry["domain"],
                        a_records=a_records,
                        technique=entry["technique"],
                        similarity_score=_similarity(original_name, cand_name),
                    )
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer,
                    dns.resolver.NoNameservers, dns.resolver.LifetimeTimeout,
                    dns.exception.Timeout, Exception):
                pass
            return None

    results = await asyncio.gather(*[_resolve(c) for c in candidates])
    registered = [r for r in results if r is not None]
    registered.sort(key=lambda c: c.similarity_score, reverse=True)

    return TyposquattingResult(
        domain=domain,
        candidates_checked=len(candidates),
        registered_candidates=registered,
        scan_duration_seconds=round(time.monotonic() - t0, 2),
    )
