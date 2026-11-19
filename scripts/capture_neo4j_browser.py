"""Capture Neo4j Browser screenshots of the permtrim graph.

Drives the real Neo4j Browser UI at http://127.0.0.1:7474:

1. connects with "No authentication" (the sandbox server runs auth-disabled),
2. runs each showcase Cypher query through the editor,
3. switches to the Graph view and screenshots the rendered graph.

Requires: Neo4j running locally, playwright + chromium installed.
"""

from __future__ import annotations

import contextlib
import sys
from pathlib import Path

from playwright.sync_api import sync_playwright

BROWSER_URL = "http://127.0.0.1:7474"
OUT_DIR = Path("/home/z/my-project/download/permtrim/docs")

# Showcase queries: (filename, cypher)
CAPTURES = [
    (
        "neo4j_hidden_paths.png",
        "Graph view: alice's permission topology — her two direct policies, "
        "the devs group with its EC2-Read policy (the hidden indirect path), "
        "and the wildcard blast radius node.",
        "MATCH path = (p:Principal {name: 'alice'})"
        "-[:MEMBER_OF|GRANTED*0..1]->(pol:Policy)-[:ALLOWS]->(a:Action) "
        "RETURN path",
    ),
    (
        "neo4j_denied_attempt.png",
        "Graph view: deploy-ci tried ec2:RunInstances and every call was "
        "denied — the ATTEMPTED edge against a principal with zero grants.",
        "MATCH path = (p:Principal {name: 'deploy-ci'})-[:ATTEMPTED]->(a:Action) RETURN path",
    ),
]


def _connect(page) -> None:
    """Open :server connect, pick 'No authentication', connect."""
    page.goto(BROWSER_URL, wait_until="networkidle")
    page.wait_for_timeout(2500)

    textarea = page.locator("textarea").first
    textarea.click()
    textarea.fill(":server connect")
    page.keyboard.press("Control+Enter")
    page.wait_for_timeout(2000)

    # the connect frame shows an editor card; click its Connect button
    connect_btn = page.locator("button", has_text="Connect").last
    connect_btn.click()
    page.wait_for_timeout(2000)

    # if an authentication dialog appears, switch to "No authentication"
    no_auth = page.locator("text=No authentication")
    if no_auth.count() > 0:
        no_auth.first.click()
        page.wait_for_timeout(800)
        page.locator("button", has_text="Connect").last.click()
        page.wait_for_timeout(2500)

    # clear the editor frame backlog for a clean screenshot
    page.keyboard.press("ControlOrMeta+l")  # clear editor history/frame
    page.wait_for_timeout(1500)


def _run_query(page, cypher: str) -> None:
    textarea = page.locator("textarea").first
    textarea.click()
    textarea.fill(cypher)
    page.keyboard.press("Control+Enter")
    page.wait_for_timeout(4000)  # let the result frame render


def _open_graph_view(page) -> None:
    """Expand the result frame's graph view if it exists."""
    for _ in range(10):
        graph_tab = page.locator("button", has_text="Graph")
        if graph_tab.count() > 0 and graph_tab.first.is_visible():
            with contextlib.suppress(Exception):
                graph_tab.first.click()
            page.wait_for_timeout(2000)
            return
        page.wait_for_timeout(800)


def main() -> int:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        page = browser.new_page(viewport={"width": 1600, "height": 1000})
        _connect(page)

        for filename, description, cypher in CAPTURES:
            _run_query(page, cypher)
            _open_graph_view(page)
            page.screenshot(path=str(OUT_DIR / filename))
            print(f"captured {OUT_DIR / filename}: {description[:60]}...")

        browser.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
