"""Web crawler — bounded same-origin crawling with configurable depth and page limits."""

from __future__ import annotations

import re
from collections import deque
from dataclasses import dataclass, field
from typing import Callable, Optional
from urllib.parse import urljoin, urlparse


@dataclass
class Page:
    """A single crawled page."""

    url: str
    status: int
    headers: dict
    body: str
    cookies: Optional[dict] = None


def same_origin(a: str, b: str) -> bool:
    """Return True if URLs a and b share the same origin (scheme + host + port)."""
    pa = urlparse(a)
    pb = urlparse(b)
    return (
        pa.scheme == pb.scheme
        and pa.netloc == pb.netloc
    )


def extract_links(base_url: str, html: str) -> list[str]:
    """Extract and resolve links from HTML, keeping only same-origin http(s) URLs.

    Uses regex to find href and src attributes, resolves relative URLs via urljoin,
    and filters to same-origin only. Returns a list of absolute URLs.
    """
    links = []

    # Pattern for href="..." or href='...' or href=...
    href_pattern = re.compile(r'href\s*=\s*["\']?([^\s"\'>;]+)["\']?', re.IGNORECASE)
    for match in href_pattern.finditer(html):
        url = match.group(1).strip()
        if url:
            try:
                absolute = urljoin(base_url, url)
                if same_origin(base_url, absolute) and absolute.startswith(("http://", "https://")):
                    links.append(absolute)
            except Exception:
                pass

    # Pattern for src="..." or src='...' or src=...
    src_pattern = re.compile(r'src\s*=\s*["\']?([^\s"\'>;]+)["\']?', re.IGNORECASE)
    for match in src_pattern.finditer(html):
        url = match.group(1).strip()
        if url:
            try:
                absolute = urljoin(base_url, url)
                if same_origin(base_url, absolute) and absolute.startswith(("http://", "https://")):
                    links.append(absolute)
            except Exception:
                pass

    return links


def crawl(
    start_url: str,
    fetch: Callable[[str], Page],
    max_pages: int = 20,
    max_depth: int = 2,
) -> list[Page]:
    """Crawl from start_url using BFS, bounded by max_pages and max_depth.

    Parameters
    ----------
    start_url:
        URL to start crawling from.
    fetch:
        A callable that takes a URL and returns a Page.
        Tests provide a fake fetcher; production builds one over httpx.
        Must never raise on a single fetch error — skip silently.
    max_pages:
        Maximum number of pages to crawl.
    max_depth:
        Maximum depth to crawl (root = 0, links from root = 1, etc.).

    Returns
    -------
    A list of Page objects in the order they were crawled.
    Never raises on individual fetch errors; silently skips them.
    """
    pages: list[Page] = []
    visited: set[str] = set()
    queue: deque[tuple[str, int]] = deque([(start_url, 0)])

    while queue and len(pages) < max_pages:
        url, depth = queue.popleft()

        # Skip if already visited or past max_depth.
        if url in visited or depth > max_depth:
            continue

        visited.add(url)

        # Fetch the page. Never raise on individual errors — skip silently.
        try:
            page = fetch(url)
            pages.append(page)
        except Exception:
            continue

        # Extract and enqueue links from this page if we haven't reached max_depth yet.
        if depth < max_depth:
            try:
                links = extract_links(page.url, page.body)
                for link in links:
                    if link not in visited and len(pages) < max_pages:
                        queue.append((link, depth + 1))
            except Exception:
                pass

    return pages


def httpx_fetcher(timeout: float = 15.0, user_agent: str = "vulnhound/0.1") -> Callable[[str], Page]:
    """Build a fetch(url)->Page backed by httpx.Client.

    Only used in production. Tests inject a fake fetcher via config.extra.
    """
    def fetch(url: str) -> Page:
        try:
            import httpx
        except ImportError:  # pragma: no cover
            raise RuntimeError("httpx is required for DAST crawling")

        with httpx.Client(timeout=timeout) as client:
            resp = client.get(url, follow_redirects=True)
            # Parse Set-Cookie headers for the cookies dict.
            cookies_dict = None
            set_cookie_headers = resp.headers.get_list("set-cookie")
            if set_cookie_headers:
                cookies_dict = {}
                for sc in set_cookie_headers:
                    # Simple parse: split on ';' and extract the name=value part.
                    if "=" in sc:
                        parts = sc.split(";")
                        name_value = parts[0].strip()
                        if "=" in name_value:
                            k, v = name_value.split("=", 1)
                            cookies_dict[k.strip()] = v.strip()

            return Page(
                url=str(resp.url),
                status=resp.status_code,
                headers=dict(resp.headers),
                body=resp.text,
                cookies=cookies_dict,
            )

    return fetch
