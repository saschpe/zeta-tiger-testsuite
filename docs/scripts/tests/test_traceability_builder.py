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

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from testsuite_docs.traceability import builder


class TraceabilityBuilderTest(unittest.TestCase):

  def test_build_traceability_covers_non_a_requirements_from_test_aspects(
      self) -> None:
    with tempfile.TemporaryDirectory() as tmp_dir_name:
      project_root = Path(tmp_dir_name)
      self._write_minimal_project(project_root)

      report = builder.build_traceability(
          project_root=project_root,
          product_status_csv=project_root / "docs/asciidoc/tables/source/product_implementation.csv",
          write_outputs=False,
      )

      self.assertIn("GS-A_5526", report.requirements)
      self.assertIn("TA_GS-A_5526_01", report.test_aspects)
      self.assertEqual(
          report.test_aspects["TA_GS-A_5526_01"]["title"],
          "TLS-Renegotiation-Indication-Extension",
      )
      self.assertTrue(
          any(link.requirement == "GS-A_5526"
              and link.test_aspect == "TA_GS-A_5526_01"
              and link.implemented
              and link.use_case == "UseCase_01" for link in report.traceability)
      )
      self.assertEqual(
          report.coverage_summary["requirements"]["vollständig abgedeckt"],
          1,
      )

  def test_parse_feature_files_uses_known_requirement_ids_without_a_regex(
      self) -> None:
    with tempfile.TemporaryDirectory() as tmp_dir_name:
      project_root = Path(tmp_dir_name)
      feature_root = project_root / "src/test/resources/features"
      feature_path = feature_root / "UserStory_TLS/UseCase_01/tls_guard.feature"
      feature_path.parent.mkdir(parents=True)
      feature_path.write_text(
          """#language: de
@UseCase_TLS_01
Funktionalität: TLS Guard

  @GS-A_5526
  @TA_GS-A_5526_01
  Szenario: TLS-Renegotiation wird geprüft
    Angenommen etwas ist vorbereitet
""",
          encoding="utf-8",
      )

      _use_cases, scenarios = builder._parse_feature_files(
          feature_root,
          user_story_anchors={},
          use_case_anchors={},
          known_requirement_ids={"GS-A_5526"},
          known_test_aspect_requirements={"TA_GS-A_5526_01": "GS-A_5526"},
      )

      self.assertEqual(len(scenarios), 1)
      self.assertEqual(scenarios[0].requirements, {"GS-A_5526"})
      self.assertEqual(scenarios[0].test_aspects, {"TA_GS-A_5526_01"})

  def test_parse_feature_files_warns_about_traceability_inconsistencies(
      self) -> None:
    with tempfile.TemporaryDirectory() as tmp_dir_name:
      project_root = Path(tmp_dir_name)
      feature_root = project_root / "src/test/resources/features"
      feature_path = feature_root / "UserStory_TLS/UseCase_01/tls_guard.feature"
      feature_path.parent.mkdir(parents=True)
      feature_path.write_text(
          """#language: de
Funktionalität: TLS Guard

  @GS-A_5526
  Szenario: Requirement ohne Testaspekt
    Angenommen etwas ist vorbereitet

  @A_0001
  @TA_GS-A_5526_01
  Szenario: Requirement passt nicht zum Testaspekt
    Angenommen etwas ist vorbereitet

  @GS-A_9999
  @TA_UNKNOWN_01
  Szenario: Unbekannte Tags
    Angenommen etwas ist vorbereitet
""",
          encoding="utf-8",
      )

      with self.assertLogs(builder.LOGGER, level="WARNING") as logs:
        builder._parse_feature_files(
            feature_root,
            user_story_anchors={},
            use_case_anchors={},
            known_requirement_ids={"A_0001", "GS-A_5526"},
            known_test_aspect_requirements={"TA_GS-A_5526_01": "GS-A_5526"},
        )

      log_output = "\n".join(logs.output)
      self.assertIn("without a test aspect tag", log_output)
      self.assertIn("do not match test aspect parent requirement", log_output)
      self.assertIn("unknown requirement tag GS-A_9999", log_output)
      self.assertIn("unknown test aspect tag TA_UNKNOWN_01", log_output)

  def test_parse_feature_files_aggregates_outline_example_tags_for_warnings(
      self) -> None:
    with tempfile.TemporaryDirectory() as tmp_dir_name:
      project_root = Path(tmp_dir_name)
      feature_root = project_root / "src/test/resources/features"
      feature_path = feature_root / "UserStory_TLS/UseCase_01/tls_guard.feature"
      feature_path.parent.mkdir(parents=True)
      feature_path.write_text(
          """#language: de
Funktionalität: TLS Guard

  @GS-A_5526
  Szenariogrundriss: Requirement am Szenario und Testaspekt am Beispiel
    Angenommen <wert> ist vorbereitet

    @TA_GS-A_5526_01
    Beispiele:
      | wert |
      | eins |
""",
          encoding="utf-8",
      )

      with self.assertNoLogs(builder.LOGGER, level="WARNING"):
        _use_cases, scenarios = builder._parse_feature_files(
            feature_root,
            user_story_anchors={},
            use_case_anchors={},
            known_requirement_ids={"GS-A_5526"},
            known_test_aspect_requirements={"TA_GS-A_5526_01": "GS-A_5526"},
        )

      self.assertEqual(len(scenarios), 2)
      combined_requirements = set().union(*(scenario.requirements for scenario in scenarios))
      combined_test_aspects = set().union(*(scenario.test_aspects for scenario in scenarios))
      self.assertEqual(combined_requirements, {"GS-A_5526"})
      self.assertEqual(combined_test_aspects, {"TA_GS-A_5526_01"})

  def test_product_not_impl_tags_do_not_affect_product_gap_status(self) -> None:
    with tempfile.TemporaryDirectory() as tmp_dir_name:
      project_root = Path(tmp_dir_name)
      self._write_minimal_project(
          project_root,
          scenario_tags=("@GS-A_5526", "@TA_GS-A_5526_01", "@product_not_impl"),
          product_status="ja",
      )

      report = builder.build_traceability(
          project_root=project_root,
          product_status_csv=project_root / "docs/asciidoc/tables/source/product_implementation.csv",
          write_outputs=False,
      )

      self.assertEqual(
          report.coverage_summary["product_gap"]["implemented_tested"],
          1,
      )
      self.assertTrue(
          any(link.requirement == "GS-A_5526" and link.implemented
              for link in report.traceability)
      )

  def test_build_traceability_renders_masvs_tables(self) -> None:
    with tempfile.TemporaryDirectory() as tmp_dir_name:
      project_root = Path(tmp_dir_name)
      self._write_minimal_project(
          project_root,
          scenario_tags=(
            "@GS-A_5526",
            "@TA_GS-A_5526_01",
            "@MASVS-NETWORK",
          ),
      )
      (project_root / "docs/masvs_mapping.csv").write_text(
          "AFO,MASVS\nGS-A_5526,NETWORK\n",
          encoding="utf-8",
      )

      report = builder.build_traceability(
          project_root=project_root,
          product_status_csv=project_root / "docs/asciidoc/tables/source/product_implementation.csv",
          write_outputs=True,
      )

      category_table = (
          project_root /
          "docs/asciidoc/tables/generated/masvs_coverage_by_category.adoc"
      ).read_text(encoding="utf-8")
      requirement_table = (
          project_root /
          "docs/asciidoc/tables/generated/masvs_coverage_by_requirement.adoc"
      ).read_text(encoding="utf-8")

      self.assertIn("|NETWORK", category_table)
      self.assertIn("|<<GS-A_5526>>", category_table)
      self.assertNotIn("Testaspekt", category_table)
      self.assertNotIn("|<<TA_GS-A_5526_01>>", category_table)
      self.assertIn("|TLS-Renegotiation wird geprüft", category_table)
      self.assertIn("|1", requirement_table)
      self.assertIn("|ja", requirement_table)
      self.assertEqual(report.coverage_summary["masvs"]["covered_requirements"], 1)

  def test_traceability_helper_functions(self) -> None:
    self.assertEqual(builder._normalise_product_flag("yes"), "ja")
    self.assertEqual(builder._normalise_product_flag("teilw."), "teilweise")
    self.assertIsNone(builder._normalise_product_flag("maybe"))
    self.assertEqual(builder._format_coverage_progress(1, 3), "33% (1/3)")
    self.assertEqual(builder._format_ratio_percent(2, 3), "2/3 (67%)")

  def _write_minimal_project(
      self,
      project_root: Path,
      *,
      scenario_tags: tuple[str, ...] = ("@GS-A_5526", "@TA_GS-A_5526_01"),
      product_status: str = "ja",
  ) -> None:
    afo_dir = project_root / "docs/asciidoc/afos/gemSpec_Krypt"
    ta_dir = project_root / "docs/asciidoc/testaspekte/gemSpec_Krypt/GS-A_5526"
    tables_source_dir = project_root / "docs/asciidoc/tables/source"
    feature_dir = project_root / "src/test/resources/features/UserStory_TLS/UseCase_01"
    afo_dir.mkdir(parents=True)
    ta_dir.mkdir(parents=True)
    tables_source_dir.mkdir(parents=True)
    feature_dir.mkdir(parents=True)

    (afo_dir / "GS-A_5526.adoc").write_text(
        "[#GS-A_5526]\n==== GS-A_5526 - TLS-Renegotiation-Indication-Extension\n",
        encoding="utf-8",
    )
    (ta_dir / "TA_GS-A_5526_01.adoc").write_text(
        "[#TA_GS-A_5526_01]\n"
        "===== TA_GS-A_5526_01 - TLS-Renegotiation-Indication-Extension\n",
        encoding="utf-8",
    )
    (tables_source_dir / "product_implementation.csv").write_text(
        f"Anforderung,Titel,umgesetzt,Hinweis\nGS-A_5526,TLS,{product_status},\n",
        encoding="utf-8",
    )
    tag_block = "\n  ".join(scenario_tags)
    (feature_dir / "tls_guard.feature").write_text(
        f"""#language: de
Funktionalität: TLS Guard

  {tag_block}
  Szenario: TLS-Renegotiation wird geprüft
    Angenommen etwas ist vorbereitet
""",
        encoding="utf-8",
    )


if __name__ == "__main__":
  unittest.main()
