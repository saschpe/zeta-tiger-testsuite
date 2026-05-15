#
# #%L
# ZETA Testsuite
# %%
# (C) achelos GmbH, 2025, licensed for gematik GmbH
# %%
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# *******
#
# For additional notes and disclaimer from gematik and in case of changes by gematik find details in the "Readme" file.
# #L%
#

"""Apply and verify MASVS tags on feature scenarios from an AFO/MASVS CSV.

The proof obligation implemented by this module is:

For every parsed scenario or examples block, let ``A`` be the set of effective
AFO tags on that block and ``M`` be the CSV mapping from AFO to MASVS category.
The feature file is correct iff ``union(M[a] for a in A)`` is a subset of the
effective ``MASVS-*`` tags on the same block.
"""

from __future__ import annotations

import argparse
import csv
import re
import sys
from collections import defaultdict
from dataclasses import dataclass, field
from io import StringIO
from pathlib import Path
from typing import Iterable, Mapping, Sequence


DEFAULT_FEATURES_ROOT = Path("src/test/resources/features")
KNOWN_MASVS_CATEGORIES = {
  "AUTH",
  "CODE",
  "CRYPTO",
  "NETWORK",
  "PLATFORM",
  "PRIVACY",
  "RESILIENCE",
  "STORAGE",
}
MASVS_CATEGORY_ALIASES = {
  "AUTHENTICATIONANDAUTHORIZATION": "AUTH",
  "AUTHENTIFICATIONANDAUTHORIZATION": "AUTH",
}

AFO_PATTERN = re.compile(r"^(?:GS-)?A_\d+(?:-\d+)?$")
TAG_PATTERN = re.compile(r"@([A-Za-z0-9_\-]+)")
FEATURE_PATTERN = re.compile(r"^(?:Funktionalität|Feature):\s*(?P<name>.+?)\s*$",
                             re.IGNORECASE)
SCENARIO_PATTERN = re.compile(
    r"^(?:Szenario(?:grundriss| Outline)?|Scenario(?: Outline)?):\s*(?P<name>.+?)\s*$",
    re.IGNORECASE,
)
EXAMPLES_PATTERN = re.compile(r"^(?:Beispiele|Examples)(?::\s*(?P<label>.*))?\s*$",
                              re.IGNORECASE)


@dataclass(frozen=True)
class MasvsTagUpdate:
  """A missing MASVS tag insertion for one scenario or examples block."""

  feature_path: Path
  insert_index: int
  line_number: int
  indent: str
  target_kind: str
  target_name: str
  afo_tags: tuple[str, ...]
  missing_tags: tuple[str, ...]


@dataclass(frozen=True)
class MasvsTaggingResult:
  """Summary returned by the MASVS tagging pass."""

  feature_files: int = 0
  parsed_blocks: int = 0
  covered_blocks: int = 0
  updates: tuple[MasvsTagUpdate, ...] = ()
  changed_files: frozenset[Path] = field(default_factory=frozenset)

  @property
  def changed_file_count(self) -> int:
    return len(self.changed_files)

  @property
  def inserted_tag_count(self) -> int:
    return sum(len(update.missing_tags) for update in self.updates)


def find_repo_root(start: Path) -> Path:
  """Locate the repository root by walking upwards to ``pom.xml``."""
  for candidate in [start.resolve(), *start.resolve().parents]:
    if (candidate / "pom.xml").exists():
      return candidate
  return start.resolve()


def load_masvs_mapping(
    csv_path: Path | str,
    *,
    stdin_text: str | None = None,
) -> dict[str, frozenset[str]]:
  """Load an AFO -> MASVS tag mapping from a CSV file.

  The CSV may use comma, semicolon or tab delimiters. With headers, the AFO
  column may be named ``AFO``, ``Anforderung`` or ``Requirement`` and the MASVS
  column may be named ``MASVS`` or ``Kategorie``. Without headers, the first
  column is interpreted as AFO and the second column as MASVS category.
  """
  text = _read_csv_text(csv_path, stdin_text=stdin_text)
  rows = _read_csv_rows(text)
  if not rows:
    raise ValueError("MASVS mapping CSV is empty.")

  afo_index, masvs_index, data_rows = _resolve_mapping_columns(rows)
  mapping: dict[str, set[str]] = defaultdict(set)
  skipped = 0
  for row in data_rows:
    if len(row) <= max(afo_index, masvs_index):
      skipped += 1
      continue
    afo_raw = row[afo_index].strip()
    masvs_raw = row[masvs_index].strip()
    if not afo_raw and not masvs_raw:
      continue
    afo = _normalize_afo(afo_raw)
    masvs = _normalize_masvs(masvs_raw)
    mapping[afo].add(masvs)

  if not mapping:
    raise ValueError(
        f"MASVS mapping CSV contains no valid AFO/MASVS rows; skipped {skipped} rows."
    )
  return {afo: frozenset(tags) for afo, tags in sorted(mapping.items())}


def tag_masvs_scenarios(
    *,
    features_root: Path,
    mapping: Mapping[str, frozenset[str]],
    write: bool,
    base_afo_fallback: bool = True,
) -> MasvsTaggingResult:
  """Add missing MASVS tags and return the resulting proof summary."""
  if not features_root.exists():
    raise FileNotFoundError(f"Feature root not found: {features_root}")

  updates: list[MasvsTagUpdate] = []
  changed_files: set[Path] = set()
  parsed_blocks = 0
  covered_blocks = 0
  feature_files = 0

  for feature_path in sorted(features_root.rglob("*.feature")):
    feature_files += 1
    file_lines = feature_path.read_text(encoding="utf-8").splitlines()
    file_updates, file_parsed, file_covered = _collect_file_updates(
        feature_path=feature_path,
        lines=file_lines,
        mapping=mapping,
        base_afo_fallback=base_afo_fallback,
    )
    parsed_blocks += file_parsed
    covered_blocks += file_covered
    updates.extend(file_updates)
    if write and file_updates:
      changed_files.add(feature_path)
      _write_feature_with_updates(feature_path, file_lines, file_updates)

  return MasvsTaggingResult(
      feature_files=feature_files,
      parsed_blocks=parsed_blocks,
      covered_blocks=covered_blocks,
      updates=tuple(updates),
      changed_files=frozenset(changed_files),
  )


def _collect_file_updates(
    *,
    feature_path: Path,
    lines: Sequence[str],
    mapping: Mapping[str, frozenset[str]],
    base_afo_fallback: bool,
) -> tuple[list[MasvsTagUpdate], int, int]:
  """Collect missing MASVS insertions for one feature file."""
  updates: list[MasvsTagUpdate] = []
  pending_tags: list[str] = []
  feature_tags: set[str] = set()
  current_scenario_tags: set[str] = set()
  parsed_blocks = 0
  covered_blocks = 0

  for line_index, raw_line in enumerate(lines):
    stripped = raw_line.strip()
    if not stripped:
      continue
    if stripped.startswith("@"):
      pending_tags.extend(TAG_PATTERN.findall(stripped))
      continue
    if stripped.startswith("#"):
      continue

    feature_match = FEATURE_PATTERN.match(stripped)
    if feature_match:
      feature_tags = set(pending_tags)
      pending_tags = []
      current_scenario_tags = set()
      continue

    scenario_match = SCENARIO_PATTERN.match(stripped)
    if scenario_match:
      scenario_tags = set(pending_tags)
      pending_tags = []
      effective_tags = feature_tags | scenario_tags
      name = scenario_match.group("name").strip()
      update = _build_update(
          feature_path=feature_path,
          line_index=line_index,
          raw_line=raw_line,
          target_kind="scenario",
          target_name=name,
          effective_tags=effective_tags,
          mapping=mapping,
          base_afo_fallback=base_afo_fallback,
      )
      parsed_blocks += 1
      if _mapped_afo_tags(effective_tags, mapping, base_afo_fallback):
        covered_blocks += 1
      if update:
        updates.append(update)
        effective_tags = effective_tags | set(update.missing_tags)
      current_scenario_tags = effective_tags
      continue

    examples_match = EXAMPLES_PATTERN.match(stripped)
    if examples_match:
      example_tags = set(pending_tags)
      pending_tags = []
      effective_tags = current_scenario_tags | example_tags
      label = examples_match.group("label") or "<unnamed>"
      update = _build_update(
          feature_path=feature_path,
          line_index=line_index,
          raw_line=raw_line,
          target_kind="examples",
          target_name=label.strip(),
          effective_tags=effective_tags,
          mapping=mapping,
          base_afo_fallback=base_afo_fallback,
      )
      parsed_blocks += 1
      if _mapped_afo_tags(effective_tags, mapping, base_afo_fallback):
        covered_blocks += 1
      if update:
        updates.append(update)
      continue

    pending_tags = []

  return updates, parsed_blocks, covered_blocks


def _build_update(
    *,
    feature_path: Path,
    line_index: int,
    raw_line: str,
    target_kind: str,
    target_name: str,
    effective_tags: set[str],
    mapping: Mapping[str, frozenset[str]],
    base_afo_fallback: bool,
) -> MasvsTagUpdate | None:
  """Build a missing tag update for one parsed block if needed."""
  required_tags = _required_masvs_tags(effective_tags, mapping, base_afo_fallback)
  if not required_tags:
    return None
  existing_tags = {tag for tag in effective_tags if tag.startswith("MASVS-")}
  missing_tags = tuple(sorted(required_tags - existing_tags))
  if not missing_tags:
    return None
  return MasvsTagUpdate(
      feature_path=feature_path,
      insert_index=line_index,
      line_number=line_index + 1,
      indent=raw_line[:len(raw_line) - len(raw_line.lstrip())],
      target_kind=target_kind,
      target_name=target_name,
      afo_tags=tuple(sorted(_mapped_afo_tags(effective_tags, mapping,
                                             base_afo_fallback))),
      missing_tags=missing_tags,
  )


def _write_feature_with_updates(
    feature_path: Path,
    lines: Sequence[str],
    updates: Sequence[MasvsTagUpdate],
) -> None:
  """Write a feature file with missing MASVS tag lines inserted."""
  next_lines = list(lines)
  for update in sorted(updates, key=lambda item: item.insert_index, reverse=True):
    tag_lines = [f"{update.indent}@{tag}" for tag in update.missing_tags]
    next_lines[update.insert_index:update.insert_index] = tag_lines
  with feature_path.open("w", encoding="utf-8", newline="\n") as handle:
    handle.write("\n".join(next_lines))
    handle.write("\n")


def _required_masvs_tags(
    tags: Iterable[str],
    mapping: Mapping[str, frozenset[str]],
    base_afo_fallback: bool,
) -> set[str]:
  """Return all MASVS tags required by mapped AFO tags."""
  required: set[str] = set()
  for afo in _mapped_afo_tags(tags, mapping, base_afo_fallback):
    required.update(mapping.get(afo, frozenset()))
    if base_afo_fallback:
      required.update(mapping.get(_base_afo(afo), frozenset()))
  return required


def _mapped_afo_tags(
    tags: Iterable[str],
    mapping: Mapping[str, frozenset[str]],
    base_afo_fallback: bool,
) -> set[str]:
  """Return effective AFO tags that are covered by the mapping."""
  mapped: set[str] = set()
  for tag in tags:
    if not AFO_PATTERN.fullmatch(tag):
      continue
    if tag in mapping or (base_afo_fallback and _base_afo(tag) in mapping):
      mapped.add(tag)
  return mapped


def _base_afo(afo: str) -> str:
  """Drop a numeric AFO suffix such as ``-01`` for fallback matching."""
  return re.sub(r"-\d+$", "", afo)


def _read_csv_text(csv_path: Path | str, *, stdin_text: str | None) -> str:
  """Read CSV text from a file path or stdin marker."""
  if str(csv_path) == "-":
    return sys.stdin.read() if stdin_text is None else stdin_text
  path = Path(csv_path)
  if not path.exists():
    raise FileNotFoundError(f"MASVS mapping CSV not found: {path}")
  return path.read_text(encoding="utf-8-sig")


def _read_csv_rows(text: str) -> list[list[str]]:
  """Parse CSV rows with delimiter sniffing."""
  sample = text[:4096]
  try:
    dialect = csv.Sniffer().sniff(sample, delimiters=",;\t")
  except csv.Error:
    dialect = csv.excel
  reader = csv.reader(StringIO(text), dialect=dialect)
  return [[cell.strip() for cell in row] for row in reader if any(cell.strip() for cell in row)]


def _resolve_mapping_columns(rows: Sequence[Sequence[str]]) -> tuple[int, int, Sequence[Sequence[str]]]:
  """Resolve AFO and MASVS columns, with fallback to the first two columns."""
  header = rows[0]
  normalized = [_normalize_header(cell) for cell in header]
  afo_index = _first_header_match(
      normalized,
      {"afo", "afoid", "anforderung", "requirement", "requirementid", "id"},
  )
  masvs_index = _first_header_match(
      normalized,
      {"masvs", "masvskategorie", "category", "kategorie", "owaspmasvs"},
  )
  if afo_index is not None and masvs_index is not None:
    return afo_index, masvs_index, rows[1:]
  if len(header) < 2:
    raise ValueError("MASVS mapping CSV needs at least two columns: AFO and MASVS.")
  return 0, 1, rows


def _first_header_match(headers: Sequence[str], candidates: set[str]) -> int | None:
  """Find the first matching normalized header index."""
  for index, header in enumerate(headers):
    if header in candidates:
      return index
  return None


def _normalize_header(value: str) -> str:
  """Normalize a CSV header for loose matching."""
  return re.sub(r"[^a-z0-9]", "", value.lower())


def _normalize_afo(value: str) -> str:
  """Normalize and validate an AFO id from CSV."""
  afo = value.strip().lstrip("@")
  if not AFO_PATTERN.fullmatch(afo):
    raise ValueError(f"Invalid AFO id in MASVS mapping CSV: {value!r}")
  return afo


def _normalize_masvs(value: str) -> str:
  """Normalize and validate a MASVS tag from CSV."""
  raw = value.strip().lstrip("@").upper().replace("_", "-")
  raw_category = raw.removeprefix("MASVS-")
  category_key = re.sub(r"[^A-Z0-9]", "", raw_category)
  category = MASVS_CATEGORY_ALIASES.get(category_key, raw_category)
  if category not in KNOWN_MASVS_CATEGORIES:
    raise ValueError(f"Invalid MASVS category in mapping CSV: {value!r}")
  return f"MASVS-{category}"


def _parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
  parser = argparse.ArgumentParser(
      prog="tag-masvs-scenarios",
      description=(
          "Apply and verify scenario MASVS tags from an AFO/MASVS CSV mapping."
      ),
  )
  parser.add_argument(
      "--mapping-csv",
      required=True,
      help="CSV with AFO and MASVS columns. Use '-' to read from stdin.",
  )
  parser.add_argument(
      "--project-root",
      type=Path,
      default=None,
      help="Repository root. Defaults to the nearest parent containing pom.xml.",
  )
  parser.add_argument(
      "--features-root",
      type=Path,
      default=None,
      help=f"Feature root. Defaults to {DEFAULT_FEATURES_ROOT}.",
  )
  parser.add_argument(
      "--check",
      action="store_true",
      help="Do not write files; fail if any required MASVS tag is missing.",
  )
  parser.add_argument(
      "--dry-run",
      action="store_true",
      help="Do not write files; print planned updates and exit successfully.",
  )
  parser.add_argument(
      "--no-base-afo-fallback",
      action="store_true",
      help="Disable matching A_12345-01 scenario tags to CSV row A_12345.",
  )
  parser.add_argument(
      "--verbose",
      action="store_true",
      help="Print every planned or applied insertion.",
  )
  return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
  """CLI entry point."""
  args = _parse_args(argv)
  project_root = args.project_root or find_repo_root(Path.cwd())
  features_root = args.features_root or project_root / DEFAULT_FEATURES_ROOT
  if args.features_root and not features_root.is_absolute():
    features_root = project_root / features_root

  mapping_csv: str | Path
  if args.mapping_csv == "-":
    mapping_csv = "-"
  else:
    mapping_csv = Path(args.mapping_csv)
    if not mapping_csv.is_absolute():
      mapping_csv = project_root / mapping_csv

  mapping = load_masvs_mapping(mapping_csv)
  should_write = not args.check and not args.dry_run
  result = tag_masvs_scenarios(
      features_root=features_root,
      mapping=mapping,
      write=should_write,
      base_afo_fallback=not args.no_base_afo_fallback,
  )

  _print_summary(result, mapping, project_root, wrote=should_write, verbose=args.verbose)
  if result.updates:
    if args.check:
      print("MASVS proof failed: missing tags remain.", file=sys.stderr)
      return 1
    if args.dry_run:
      return 0

  proof = tag_masvs_scenarios(
      features_root=features_root,
      mapping=mapping,
      write=False,
      base_afo_fallback=not args.no_base_afo_fallback,
  )
  if proof.updates:
    _print_updates(proof.updates, project_root)
    print("MASVS proof failed after applying updates.", file=sys.stderr)
    return 1

  print(
      "PROVEN: for every parsed scenario/examples block, "
      "required MASVS tags from the CSV mapping are present."
  )
  return 0


def _print_summary(
    result: MasvsTaggingResult,
    mapping: Mapping[str, frozenset[str]],
    project_root: Path,
    *,
    wrote: bool,
    verbose: bool,
) -> None:
  """Print a compact proof/update summary."""
  print(f"Loaded AFO/MASVS mappings: {len(mapping)}")
  print(f"Feature files scanned: {result.feature_files}")
  print(f"Scenario/examples blocks parsed: {result.parsed_blocks}")
  print(f"Blocks with mapped AFO tags: {result.covered_blocks}")
  print(f"Missing MASVS tag insertions: {result.inserted_tag_count}")
  if wrote:
    print(f"Feature files changed: {result.changed_file_count}")
  if verbose and result.updates:
    _print_updates(result.updates, project_root)


def _print_updates(updates: Sequence[MasvsTagUpdate], project_root: Path) -> None:
  """Print planned or remaining MASVS tag updates."""
  for update in updates:
    path = _format_path(update.feature_path, project_root)
    tags = ", ".join(f"@{tag}" for tag in update.missing_tags)
    afos = ", ".join(f"@{afo}" for afo in update.afo_tags)
    print(
        f"{path}:{update.line_number}: add {tags} to {update.target_kind} "
        f"{update.target_name!r} for {afos}"
    )


def _format_path(path: Path, project_root: Path) -> str:
  """Format paths relative to the project root when possible."""
  try:
    return str(path.relative_to(project_root))
  except ValueError:
    return str(path)


if __name__ == "__main__":
  raise SystemExit(main())
