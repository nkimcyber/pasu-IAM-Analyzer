#!/usr/bin/env python3
"""Synchronize AWS Service Authorization Reference into Pasu catalog.

This script fetches the AWS Service Authorization Reference index page,
discovers per-service authorization pages, extracts action metadata,
normalizes it into Pasu's catalog schema v1, compares it against the current
canonical snapshot, and writes diff reports.

Safe-write behavior:
- Always writes diff reports.
- Only overwrites the canonical catalog when validation passes.
- Uses a temporary file plus atomic replace for canonical writes.

Usage:
    python scripts/sync_aws_catalog.py --dry-run
    python scripts/sync_aws_catalog.py --write
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import re
import sys
import tempfile
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from html import unescape
from html.parser import HTMLParser
from pathlib import Path
from typing import Any
from urllib.parse import urljoin

import httpx

LOGGER = logging.getLogger("sync_aws_catalog")

INDEX_URL = (
    "https://docs.aws.amazon.com/service-authorization/latest/reference/"
    "reference_policies_actions-resources-contextkeys.html"
)

SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parent

CANONICAL_CATALOG_PATH = REPO_ROOT / "app" / "data" / "aws_catalog.json"
RISKY_ACTIONS_PATH = REPO_ROOT / "app" / "rules" / "risky_actions.yaml"
DIFF_JSON_PATH = REPO_ROOT / "reports" / "aws_catalog_diff.json"
DIFF_MD_PATH = REPO_ROOT / "reports" / "aws_catalog_diff.md"

HTTP_TIMEOUT = 30.0
USER_AGENT = "pasu-aws-catalog-sync/1.0"

REQUIRED_ACTIONS = {"iam:PassRole", "s3:GetObject", "ec2:RunInstances"}
DISALLOWED_ACTION_NAMES = {
    "Action",
    "Actions",
    "ResourceType",
    "ResourceTypes",
    "ConditionKey",
    "ConditionKeys",
    "DependentAction",
    "DependentActions",
}


@dataclass(frozen=True)
class ActionMetadata:
    """Normalized action metadata for Pasu catalog schema v1."""

    service: str
    name: str
    access_level: str
    resource_types: list[str]
    condition_keys: list[str]
    dependent_actions: list[str]


class ActionsTableParser(HTMLParser):
    """Parse the first Actions table after the relevant heading.

    The AWS service authorization pages contain multiple tables. This parser
    captures only the first table following a heading that starts with
    "Actions defined by".
    """

    def __init__(self) -> None:
        """Initialize parser state."""
        super().__init__(convert_charrefs=True)
        self._capture_heading = False
        self._heading_parts: list[str] = []
        self._actions_section_seen = False

        self._in_table = False
        self._table_done = False
        self._table_depth = 0

        self._in_row = False
        self._in_cell = False
        self._current_cell_parts: list[str] = []
        self._current_row: list[str] = []

        self.current_headers: list[str] = []
        self.rows: list[list[str]] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        """Handle HTML start tags."""
        if self._table_done:
            return

        lower = tag.lower()
        if lower in {"h1", "h2", "h3", "h4", "h5", "h6"}:
            self._capture_heading = True
            self._heading_parts = []
            return

        if self._actions_section_seen and lower == "table" and not self._in_table:
            self._in_table = True
            self._table_depth = 1
            return

        if self._in_table and lower == "table":
            self._table_depth += 1
            return

        if not self._in_table:
            return

        if lower == "tr":
            self._in_row = True
            self._current_row = []
            return

        if lower in {"td", "th"} and self._in_row:
            self._in_cell = True
            self._current_cell_parts = []

    def handle_endtag(self, tag: str) -> None:
        """Handle HTML end tags."""
        if self._table_done:
            return

        lower = tag.lower()

        if self._capture_heading and lower in {"h1", "h2", "h3", "h4", "h5", "h6"}:
            heading = _collapse_whitespace(" ".join(self._heading_parts))
            self._capture_heading = False
            if heading.lower().startswith("actions defined by"):
                self._actions_section_seen = True
            return

        if not self._in_table:
            return

        if lower in {"td", "th"} and self._in_cell:
            self._in_cell = False
            cell_text = _clean_cell_text(" ".join(self._current_cell_parts))
            self._current_row.append(cell_text)
            self._current_cell_parts = []
            return

        if lower == "tr" and self._in_row:
            self._in_row = False
            if self._current_row:
                if not self.current_headers:
                    self.current_headers = [c.lower() for c in self._current_row]
                else:
                    self.rows.append(self._current_row[:])
            self._current_row = []
            return

        if lower == "table":
            self._table_depth -= 1
            if self._table_depth <= 0:
                self._in_table = False
                self._table_done = True

    def handle_data(self, data: str) -> None:
        """Handle text nodes."""
        if self._capture_heading:
            self._heading_parts.append(data)
            return
        if self._in_table and self._in_cell:
            self._current_cell_parts.append(data)


def configure_logging() -> None:
    """Configure process logging."""
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
    )


def parse_args() -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--dry-run", action="store_true", help="Do not overwrite canonical catalog")
    mode.add_argument("--write", action="store_true", help="Overwrite canonical catalog when validation passes")
    return parser.parse_args()


def _collapse_whitespace(value: str) -> str:
    """Collapse consecutive whitespace into a single space."""
    return " ".join(value.split()).strip()


def _clean_cell_text(value: str) -> str:
    """Normalize cell text."""
    return _collapse_whitespace(unescape(value))


def fetch_text(client: httpx.Client, url: str) -> str:
    """Fetch text content from a URL."""
    try:
        response = client.get(url, follow_redirects=True)
        response.raise_for_status()
        LOGGER.info(
            'HTTP Request: GET %s "HTTP/%s %s %s"',
            url,
            response.http_version,
            response.status_code,
            response.reason_phrase,
        )
        return response.text
    except httpx.HTTPError as exc:
        LOGGER.error("Failed to fetch URL %s: %s", url, exc)
        raise RuntimeError(f"Failed to fetch URL: {url}") from exc


def discover_service_urls(client: httpx.Client) -> list[str]:
    """Fetch the index page and discover per-service reference URLs."""
    html = fetch_text(client, INDEX_URL)
    hrefs = set(re.findall(r'href="([^"]+)"', html, flags=re.IGNORECASE))

    urls: list[str] = []
    for href in sorted(hrefs):
        if href.startswith("#"):
            continue
        if "reference_policies_actions-resources-contextkeys.html" in href:
            continue
        if "list_" not in href:
            continue
        if not href.endswith(".html"):
            continue
        urls.append(urljoin(INDEX_URL, href))

    if not urls:
        LOGGER.error("No service documentation links found on index page.")
        raise RuntimeError("Could not discover AWS service authorization pages.")
    return urls


def extract_service_prefix(html: str, service_url: str) -> str:
    """Extract service prefix from a service authorization page."""
    text_only = re.sub(r"<[^>]+>", " ", html)
    text_only = _collapse_whitespace(unescape(text_only))
    patterns = [
        r"service prefix:\s*`?([a-z0-9-]+)`?",
        r"\(service prefix:\s*`?([a-z0-9-]+)`?\)",
    ]
    for pattern in patterns:
        match = re.search(pattern, text_only, flags=re.IGNORECASE)
        if match:
            return match.group(1)
    LOGGER.error("Could not extract service prefix from '%s'.", service_url)
    raise RuntimeError(f"Could not determine service prefix: {service_url}")


def normalize_access_level(value: str) -> str:
    """Normalize AWS access level values into Pasu schema values."""
    normalized = value.strip()
    allowed = {"Read", "Write", "List", "Tagging", "Permissions management"}
    return normalized if normalized in allowed else "Unknown"


def normalize_action_name(raw: str) -> str | None:
    """Normalize a raw action cell into an action name or None.

    Args:
        raw: Raw text from the Actions column.

    Returns:
        Normalized action name or None when the value should be rejected.
    """
    value = _collapse_whitespace(raw)
    value = re.sub(r"\s*\[permission only\]\s*$", "", value, flags=re.IGNORECASE)
    value = value.strip()

    if not value:
        return None
    if value in DISALLOWED_ACTION_NAMES:
        return None
    if ":" in value or " " in value:
        return None
    if any(token in value for token in ["*", "/", "${", "<", ">"]):
        return None
    if not value[0].isalpha():
        return None
    if not re.match(r"^[A-Za-z][A-Za-z0-9]*$", value):
        return None
    return value


def _extract_action_like_tokens(value: str) -> list[str]:
    """Extract fully-qualified action tokens from metadata cells."""
    if not value:
        return []
    return re.findall(r"\b[a-z0-9-]+:[A-Z][A-Za-z0-9]+\b", value)


def _extract_condition_key_tokens(value: str) -> list[str]:
    """Extract condition-key tokens from metadata cells."""
    if not value:
        return []
    tokens = re.findall(r"\b(?:aws|[a-z0-9-]+):[^\s,;]+", value)
    return [token for token in tokens if not re.match(r"^[a-z0-9-]+:[A-Z][A-Za-z0-9]+$", token)]


def _extract_resource_type_tokens(value: str) -> list[str]:
    """Extract resource-type tokens from metadata cells."""
    if not value:
        return []
    tokens = re.findall(r"\b[a-zA-Z][a-zA-Z0-9*.-]*\b", value)
    result: list[str] = []
    for token in tokens:
        if token in {"ARN", "ARNs"}:
            continue
        if ":" in token:
            continue
        if not re.match(r"^[a-z][a-zA-Z0-9*.-]*$", token):
            continue
        result.append(token)
    return result


def _sorted_unique(items: list[str]) -> list[str]:
    """Return deterministically sorted unique values."""
    return sorted({item.strip() for item in items if item and item.strip()})


def parse_actions_table(service_url: str, html: str) -> dict[str, ActionMetadata]:
    """Parse one service authorization page into action metadata."""
    parser = ActionsTableParser()
    parser.feed(html)

    if not parser.rows or not parser.current_headers:
        LOGGER.error("No parseable Actions table found for '%s'.", service_url)
        raise RuntimeError(f"Could not parse actions table: {service_url}")

    headers = [header.lower() for header in parser.current_headers]
    header_index = {header: idx for idx, header in enumerate(headers)}

    action_idx = header_index.get("actions")
    access_idx = header_index.get("access level")
    resource_idx = header_index.get("resource types (*required)")
    if resource_idx is None:
        resource_idx = header_index.get("resource types")
    condition_idx = header_index.get("condition keys")
    dependent_idx = header_index.get("dependent actions")

    if action_idx is None or access_idx is None:
        LOGGER.error("Missing mandatory Actions/Access Level columns for '%s'.", service_url)
        raise RuntimeError(f"Unexpected actions table layout: {service_url}")

    service_prefix = extract_service_prefix(html, service_url)
    actions: dict[str, ActionMetadata] = {}
    previous_action_key: str | None = None

    for row in parser.rows:
        padded = row + [""] * max(0, len(headers) - len(row))
        raw_action_value = padded[action_idx].strip() if action_idx < len(padded) else ""
        access_value = padded[access_idx].strip() if access_idx < len(padded) else ""
        resource_value = padded[resource_idx].strip() if resource_idx is not None and resource_idx < len(padded) else ""
        condition_value = padded[condition_idx].strip() if condition_idx is not None and condition_idx < len(padded) else ""
        dependent_value = padded[dependent_idx].strip() if dependent_idx is not None and dependent_idx < len(padded) else ""

        action_name = normalize_action_name(raw_action_value)
        access_level = normalize_access_level(access_value)

        if action_name is None and previous_action_key:
            metadata = actions[previous_action_key]
            actions[previous_action_key] = ActionMetadata(
                service=metadata.service,
                name=metadata.name,
                access_level=metadata.access_level,
                resource_types=_sorted_unique(metadata.resource_types + _extract_resource_type_tokens(resource_value)),
                condition_keys=_sorted_unique(metadata.condition_keys + _extract_condition_key_tokens(condition_value)),
                dependent_actions=_sorted_unique(metadata.dependent_actions + _extract_action_like_tokens(dependent_value)),
            )
            continue

        if action_name is None:
            continue
        if access_level == "Unknown":
            continue

        key = f"{service_prefix}:{action_name}"
        actions[key] = ActionMetadata(
            service=service_prefix,
            name=action_name,
            access_level=access_level,
            resource_types=_sorted_unique(_extract_resource_type_tokens(resource_value)),
            condition_keys=_sorted_unique(_extract_condition_key_tokens(condition_value)),
            dependent_actions=_sorted_unique(_extract_action_like_tokens(dependent_value)),
        )
        previous_action_key = key

    if not actions:
        LOGGER.error("Parsed zero actions from '%s'.", service_url)
        raise RuntimeError(f"No actions parsed from service page: {service_url}")
    return actions


def build_catalog(client: httpx.Client) -> dict[str, Any]:
    """Fetch AWS docs and build the normalized catalog structure."""
    all_actions: dict[str, ActionMetadata] = {}
    service_urls = discover_service_urls(client)
    LOGGER.info("Discovered %d service authorization pages.", len(service_urls))

    for index, url in enumerate(service_urls, start=1):
        LOGGER.info("[%d/%d] Parsing %s", index, len(service_urls), url)
        html = fetch_text(client, url)
        service_actions = parse_actions_table(url, html)
        all_actions.update(service_actions)

    return {
        "version": 1,
        "generated_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
        "source": {"name": "AWS Service Authorization Reference"},
        "actions": {
            action: asdict(metadata)
            for action, metadata in sorted(all_actions.items(), key=lambda item: item[0])
        },
    }


def load_json_file(path: Path) -> dict[str, Any] | None:
    """Load a JSON file if it exists."""
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        LOGGER.error("Invalid JSON in '%s': %s", path, exc)
        raise RuntimeError(f"Invalid JSON file: {path}") from exc


def load_risky_actions(path: Path) -> set[str]:
    """Load classified risky actions from risky_actions.yaml."""
    try:
        raw = path.read_text(encoding="utf-8")
        data = json.loads(raw)
    except OSError as exc:
        LOGGER.error("Failed to read '%s': %s", path, exc)
        raise RuntimeError(f"Failed to read risky actions file: {path}") from exc
    except json.JSONDecodeError as exc:
        LOGGER.error("Invalid JSON-compatible YAML in '%s': %s", path, exc)
        raise RuntimeError(f"Invalid risky actions file: {path}") from exc

    classified: set[str] = set()
    for key in ("high_risk_actions", "medium_risk_actions", "context_medium_actions"):
        values = data.get(key, [])
        if isinstance(values, dict):
            classified.update(str(k) for k in values.keys())
        elif isinstance(values, list):
            classified.update(str(v) for v in values)
    return {value.strip().lower() for value in classified if value.strip()}


def diff_catalogs(previous: dict[str, Any] | None, current: dict[str, Any], classified_actions: set[str]) -> dict[str, Any]:
    """Compute catalog diff and unclassified-action reports."""
    previous_actions = previous.get("actions", {}) if previous else {}
    current_actions = current.get("actions", {})

    previous_keys = set(previous_actions.keys())
    current_keys = set(current_actions.keys())

    new_actions = sorted(current_keys - previous_keys)
    removed_actions = sorted(previous_keys - current_keys)
    common_actions = sorted(previous_keys & current_keys)

    changed_actions: list[dict[str, Any]] = []
    changed_count = 0
    for action in common_actions:
        previous_meta = previous_actions[action]
        current_meta = current_actions[action]
        changes: dict[str, Any] = {}
        for field in ("access_level", "resource_types", "condition_keys", "dependent_actions"):
            if previous_meta.get(field) != current_meta.get(field):
                changes[field] = {"previous": previous_meta.get(field), "current": current_meta.get(field)}
        if changes:
            changed_actions.append({"action": action, "changes": changes})
            changed_count += 1

    new_unclassified_actions = sorted(action for action in new_actions if action.lower() not in classified_actions)
    services_with_new_unclassified_actions = sorted({action.split(":", 1)[0] for action in new_unclassified_actions})

    return {
        "generated_at": current["generated_at"],
        "source": current["source"]["name"],
        "count_summary": {
            "previous_action_count": len(previous_keys),
            "current_action_count": len(current_keys),
            "new_action_count": len(new_actions),
            "removed_action_count": len(removed_actions),
            "changed_action_count": changed_count,
            "new_unclassified_action_count": len(new_unclassified_actions),
        },
        "new_actions": new_actions,
        "removed_actions": removed_actions,
        "changed_actions": changed_actions,
        "new_unclassified_actions": new_unclassified_actions,
        "services_with_new_unclassified_actions": services_with_new_unclassified_actions,
    }


def render_markdown_report(diff: dict[str, Any]) -> str:
    """Render a human-readable Markdown diff report."""
    summary = diff["count_summary"]
    lines = [
        "# AWS Catalog Diff Report",
        "",
        f"Generated at: `{diff['generated_at']}`",
        f"Source: `{diff['source']}`",
        "",
        "## Summary",
        "",
        f"- Previous action count: {summary['previous_action_count']}",
        f"- Current action count: {summary['current_action_count']}",
        f"- New actions: {summary['new_action_count']}",
        f"- Removed actions: {summary['removed_action_count']}",
        f"- Changed actions: {summary['changed_action_count']}",
        f"- New unclassified actions: {summary['new_unclassified_action_count']}",
        "",
    ]
    _append_markdown_list(lines, "New actions", diff["new_actions"])
    _append_markdown_list(lines, "Removed actions", diff["removed_actions"])
    lines.extend(["## Changed actions", ""])
    if diff["changed_actions"]:
        for item in diff["changed_actions"]:
            lines.append(f"- `{item['action']}`")
            for field, values in item["changes"].items():
                lines.append(f"  - `{field}`: `{values['previous']}` → `{values['current']}`")
        lines.append("")
    else:
        lines.extend(["No changed actions.", ""])
    _append_markdown_list(lines, "New unclassified actions", diff["new_unclassified_actions"])
    _append_markdown_list(lines, "Services with new unclassified actions", diff["services_with_new_unclassified_actions"])
    return "\n".join(lines).rstrip() + "\n"


def _append_markdown_list(lines: list[str], title: str, items: list[str]) -> None:
    """Append one titled Markdown bullet list."""
    lines.extend([f"## {title}", ""])
    if items:
        lines.extend([f"- `{item}`" for item in items])
        lines.append("")
    else:
        lines.extend([f"No {title.lower()}.", ""])


def write_json(path: Path, payload: dict[str, Any]) -> None:
    """Write formatted JSON to disk."""
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(payload, indent=2, sort_keys=False) + "\n", encoding="utf-8")
    except OSError as exc:
        LOGGER.error("Failed to write '%s': %s", path, exc)
        raise RuntimeError(f"Failed to write file: {path}") from exc


def atomic_write_json(path: Path, payload: dict[str, Any]) -> None:
    """Atomically write formatted JSON to disk via a temporary file."""
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=path.parent, delete=False) as tmp:
            tmp.write(json.dumps(payload, indent=2, sort_keys=False) + "\n")
            temp_name = tmp.name
        os.replace(temp_name, path)
    except OSError as exc:
        LOGGER.error("Failed to atomically write '%s': %s", path, exc)
        raise RuntimeError(f"Failed to write file atomically: {path}") from exc


def write_text(path: Path, content: str) -> None:
    """Write plain text to disk."""
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
    except OSError as exc:
        LOGGER.error("Failed to write '%s': %s", path, exc)
        raise RuntimeError(f"Failed to write file: {path}") from exc


def validate_catalog(current_catalog: dict[str, Any], previous_catalog: dict[str, Any] | None, diff: dict[str, Any]) -> None:
    """Validate a newly built catalog before overwriting canonical snapshot.

    Raises:
        RuntimeError: If any validation gate fails.
    """
    actions = sorted(current_catalog.get("actions", {}).keys())
    total_actions = len(actions)
    if total_actions <= 0:
        LOGGER.error("Validation failed: total_actions is zero.")
        raise RuntimeError("Validation failed: current catalog has zero actions")

    suspicious: list[str] = []
    for action in actions:
        if ":" not in action:
            suspicious.append(action)
            continue
        service, name = action.split(":", 1)
        if (
            not re.match(r"^[a-z0-9-]+$", service)
            or not re.match(r"^[A-Za-z][A-Za-z0-9]*$", name)
            or "${" in name
            or "<" in name
            or ">" in name
            or "/" in name
        ):
            suspicious.append(action)
    if suspicious:
        LOGGER.error("Validation failed: suspicious action keys detected: %s", suspicious[:50])
        raise RuntimeError("Validation failed: suspicious action keys detected")

    missing_required = sorted(action for action in REQUIRED_ACTIONS if action not in current_catalog["actions"])
    if missing_required:
        LOGGER.error("Validation failed: required actions missing: %s", missing_required)
        raise RuntimeError("Validation failed: required actions missing")

    previous_count = 0
    if previous_catalog:
        previous_count = len(previous_catalog.get("actions", {}))
    current_count = total_actions
    if previous_count > 0 and current_count < int(previous_count * 0.7):
        LOGGER.error(
            "Validation failed: current action count dropped too far. previous=%d current=%d",
            previous_count,
            current_count,
        )
        raise RuntimeError("Validation failed: current action count dropped unexpectedly")

    summary = diff["count_summary"]
    if previous_count > 0:
        removed_count = summary["removed_action_count"]
        new_count = summary["new_action_count"]
        if removed_count > int(previous_count * 0.3) and new_count < int(removed_count * 0.1):
            LOGGER.error(
                "Validation failed: removed actions unusually high. removed=%d new=%d previous=%d",
                removed_count,
                new_count,
                previous_count,
            )
            raise RuntimeError("Validation failed: removed actions unusually high")


def main() -> None:
    """Entry point for AWS catalog sync."""
    configure_logging()
    args = parse_args()

    headers = {"User-Agent": USER_AGENT}
    with httpx.Client(timeout=HTTP_TIMEOUT, follow_redirects=True, headers=headers) as client:
        current_catalog = build_catalog(client)

    previous_catalog = load_json_file(CANONICAL_CATALOG_PATH)
    classified_actions = load_risky_actions(RISKY_ACTIONS_PATH)
    diff = diff_catalogs(previous_catalog, current_catalog, classified_actions)

    write_json(DIFF_JSON_PATH, diff)
    write_text(DIFF_MD_PATH, render_markdown_report(diff))

    if args.write:
        validate_catalog(current_catalog, previous_catalog, diff)
        atomic_write_json(CANONICAL_CATALOG_PATH, current_catalog)
        LOGGER.info("Updated canonical catalog: %s", CANONICAL_CATALOG_PATH)
    else:
        LOGGER.info("Dry run complete; canonical catalog not modified: %s", CANONICAL_CATALOG_PATH)

    LOGGER.info("Wrote diff JSON report: %s", DIFF_JSON_PATH)
    LOGGER.info("Wrote diff Markdown report: %s", DIFF_MD_PATH)
    LOGGER.info(
        "Summary: prev=%d current=%d new=%d removed=%d changed=%d new_unclassified=%d",
        diff["count_summary"]["previous_action_count"],
        diff["count_summary"]["current_action_count"],
        diff["count_summary"]["new_action_count"],
        diff["count_summary"]["removed_action_count"],
        diff["count_summary"]["changed_action_count"],
        diff["count_summary"]["new_unclassified_action_count"],
    )


if __name__ == "__main__":
    try:
        main()
    except RuntimeError as exc:
        LOGGER.error("AWS catalog sync failed: %s", exc)
        sys.exit(1)
