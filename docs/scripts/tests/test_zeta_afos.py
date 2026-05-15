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

import io
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

from testsuite_docs import zeta_afos


class ZetaAfosTest(unittest.TestCase):

  def test_main_generates_filtered_requirements_and_updates_readme(self) -> None:
    with tempfile.TemporaryDirectory() as tmp_dir_name:
      tmp_dir = Path(tmp_dir_name)
      input_xml = tmp_dir / "gemVZ_Afo_ZETA_Guard_V_1.3.0-0_V1.0.0.xml"
      output_dir = tmp_dir / "generated"
      readme_path = tmp_dir / "readme.adoc"
      references_path = tmp_dir / "02_referenzen.adoc"
      introduction_path = tmp_dir / "03_einleitung.adoc"
      zeta_guard_components_path = tmp_dir / "zeta_guard_komponenten.adoc"

      input_xml.write_text(
          """<catalog>
  <documents>
    <document>
      <denotation>Test-Spezifikation</denotation>
      <id>gemSpec_Test</id>
      <version>1.2.3</version>
    </document>
    <document>
      <denotation>Spezifikation Zero Trust Access (ZETA)</denotation>
      <id>gemSpec_ZETA</id>
      <version>1.3.0</version>
    </document>
    <document>
      <denotation>Übergreifende Spezifikation Verwendung kryptographischer Algorithmen in der Telematikinfrastruktur</denotation>
      <id>gemSpec_Krypt</id>
      <version>2.47.0</version>
    </document>
  </documents>
  <requirements>
    <requirement id="A_0001">
      <testProcedure>Festlegungen zur funktionalen Eignung "Produkttest/Produktübergreifender Test"</testProcedure>
      <sourceDocumentId>gemSpec_Test</sourceDocumentId>
      <title>Erster Titel</title>
      <description>Mehrzeilig&#160;
        mit  Leerzeichen</description>
    </requirement>
    <requirement id="A_0002">
      <testProcedure>Andere Festlegung</testProcedure>
      <sourceDocumentId>gemSpec_Test</sourceDocumentId>
      <title>Zweiter Titel</title>
      <description>Wird herausgefiltert</description>
    </requirement>
  </requirements>
</catalog>
""",
          encoding="utf-8",
      )
      readme_path.write_text(
          """== Identifizierte Anforderungen

=== Anforderungen gemVZ AFO ZETA Guard (Produkttest 3.1.1)

veralteter Inhalt

=== Bestehender Abschnitt

bleibt erhalten
""",
          encoding="utf-8",
      )
      references_path.write_text(
          "* {gemVZ_Afo_ZETA_Guard}[gemVZ_Afo_ZETA_Guard_V_1.2.1-0]: Version 1.0.0_CC\n",
          encoding="utf-8",
      )
      introduction_path.write_text(
          """-  https://old.example.invalid/["Verzeichnis von Anforderungen Prüfvorschrift Zero Trust Access (ZETA) Guard"]
*gemVZ_Afo_ZETA_Guard_1.2.1-0_V1.0.0_CC*.
""",
          encoding="utf-8",
      )
      zeta_guard_components_path.write_text(
          'Quelle: {gemSpec_ZETA}[gemSpec_ZETA], Abschnitt 3 "Einordnung in die TI 2.0",\n',
          encoding="utf-8",
      )

      stdout = io.StringIO()
      with patch.object(zeta_afos, "ROOT_README", readme_path), patch.object(
          zeta_afos, "REFERENCES_CHAPTER", references_path), patch.object(
              zeta_afos, "INTRODUCTION_CHAPTER",
              introduction_path), patch.object(
                  zeta_afos, "ZETA_GUARD_COMPONENTS",
                  zeta_guard_components_path), redirect_stdout(stdout):
        exit_code = zeta_afos.main([
            "--input-xml",
            str(input_xml),
            "--output-dir",
            str(output_dir),
            "--force",
        ])

      self.assertEqual(exit_code, 0)
      self.assertEqual(
          stdout.getvalue().strip(),
          f"Generated 1 requirements in {output_dir.as_posix()}",
      )

      generated_files = sorted(path.relative_to(output_dir).as_posix()
                               for path in output_dir.rglob("*.adoc"))
      self.assertEqual(generated_files, ["gemSpec_Test/A_0001.adoc"])

      requirement_content = (output_dir / "gemSpec_Test" /
                             "A_0001.adoc").read_text(encoding="utf-8")
      self.assertEqual(
          requirement_content,
          "[#A_0001]\n==== A_0001 - Erster Titel\n\nMehrzeilig mit Leerzeichen\n",
      )

      readme_content = readme_path.read_text(encoding="utf-8")
      self.assertIn(
          "==== Test-Spezifikation (gemSpec_Test V1.2.3)",
          readme_content,
      )
      self.assertIn("include::gemSpec_Test/A_0001.adoc[]", readme_content)
      self.assertIn("=== Bestehender Abschnitt", readme_content)
      self.assertNotIn("veralteter Inhalt", readme_content)
      self.assertNotIn("A_0002", readme_content)
      self.assertIn(
          "gemVZ_Afo_ZETA_Guard_V_1.3.0-0_V1.0.0/",
          readme_content,
      )
      self.assertIn(
          "Kurzbezeichnung: gemSpec_Krypt, Version: 2.47.0",
          readme_content,
      )

      references_content = references_path.read_text(encoding="utf-8")
      self.assertIn(
          "* https://gemspec.gematik.de/docs/gemSpec/gemSpec_ZETA/gemSpec_ZETA_V1.3.0[Spezifikation Zero Trust Access (ZETA)]: Version 1.3.0",
          references_content,
      )
      self.assertIn(
          "* https://gemspec.gematik.de/docs/gemSpec/gemSpec_Krypt/gemSpec_Krypt_V2.47.0[Übergreifende Spezifikation Verwendung kryptographischer Algorithmen in der Telematikinfrastruktur]: Version 2.47.0",
          references_content,
      )
      self.assertIn(
          "* https://gemspec.gematik.de/docs/gemVZ/gemVZ_Afo_ZETA_Guard/gemVZ_Afo_ZETA_Guard_V_1.3.0-0_V1.0.0/[gemVZ_Afo_ZETA_Guard_V_1.3.0-0]: Version 1.0.0",
          references_content,
      )
      self.assertIn(
          "gemVZ_Afo_ZETA_Guard_V_1.3.0-0_V1.0.0",
          introduction_path.read_text(encoding="utf-8"),
      )
      self.assertIn(
          "https://gemspec.gematik.de/docs/gemSpec/gemSpec_ZETA/gemSpec_ZETA_V1.3.0",
          zeta_guard_components_path.read_text(encoding="utf-8"),
      )

  def test_main_smoke_runs_against_checked_in_xml_snapshot(self) -> None:
    repository_root = Path(__file__).resolve().parents[3]
    input_xml = repository_root / zeta_afos.DEFAULT_XML
    self.assertTrue(input_xml.exists(), input_xml.as_posix())

    with tempfile.TemporaryDirectory() as tmp_dir_name:
      output_dir = Path(tmp_dir_name) / "generated"
      stdout = io.StringIO()
      with redirect_stdout(stdout):
        exit_code = zeta_afos.main([
            "--input-xml",
            str(input_xml),
            "--output-dir",
            str(output_dir),
            "--no-readme",
            "--force",
        ])

      self.assertEqual(exit_code, 0)
      generated_files = sorted(output_dir.rglob("*.adoc"))
      self.assertGreater(len(generated_files), 0)
      self.assertRegex(
          stdout.getvalue().strip(),
          r"^Generated \d+ requirements in .+$",
      )

      first_requirement = generated_files[0].read_text(encoding="utf-8")
      self.assertIn("[#", first_requirement)
      self.assertIn("==== ", first_requirement)


if __name__ == "__main__":
  unittest.main()
