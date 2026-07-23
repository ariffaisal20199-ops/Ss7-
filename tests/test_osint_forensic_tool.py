import sqlite3
import tempfile
import unittest
from pathlib import Path

from osint_forensic_tool import (
    build_keyword_profile,
    build_report,
    generate_dork_suggestions,
    inspect_sqlite_db,
)


class OsintForensicToolTests(unittest.TestCase):
    def test_build_keyword_profile(self):
        profile = build_keyword_profile("Alice Smith cyber weather geometry")
        self.assertEqual(profile["query_terms"], ["alice", "smith", "cyber", "weather", "geometry"])
        self.assertIn("social_engineering_risk", profile["risk_flags"])
        self.assertIn("weather", profile["context_tags"])

    def test_generate_dork_suggestions(self):
        dorks = generate_dork_suggestions("alice smith")
        self.assertGreaterEqual(len(dorks), 3)
        self.assertTrue(any("site:" in dork for dork in dorks))

    def test_inspect_sqlite_db(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            db_path = Path(tmp_dir) / "demo.db"
            conn = sqlite3.connect(db_path)
            conn.execute("CREATE TABLE people (id INTEGER PRIMARY KEY, name TEXT, note TEXT)")
            conn.execute("INSERT INTO people (name, note) VALUES (?, ?)", ("Alice", "weather"))
            conn.commit()
            conn.close()

            result = inspect_sqlite_db(str(db_path))
            self.assertIn("people", result["tables"])
            self.assertEqual(result["tables"]["people"]["row_count"], 1)

    def test_build_report_contains_sections(self):
        report = build_report("Alice Smith", input_path="/tmp")
        self.assertIn("query", report)
        self.assertIn("keyword_profile", report)
        self.assertIn("dork_suggestions", report)
        self.assertIn("sqlite_analysis", report)


if __name__ == "__main__":
    unittest.main()
