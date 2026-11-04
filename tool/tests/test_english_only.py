from pathlib import Path
import unittest


TOOL_ROOT = Path(__file__).resolve().parents[1]
TEXT_EXTENSIONS = {".py", ".html", ".md", ".json", ".txt", ".sh"}
# Turkish-specific letters, represented as code points so this source remains ASCII.
FORBIDDEN_CODEPOINTS = {
    0x00E7, 0x011F, 0x0131, 0x00F6, 0x015F, 0x00FC,
    0x00C7, 0x011E, 0x0130, 0x00D6, 0x015E, 0x00DC,
}


class EnglishOnlyToolTests(unittest.TestCase):
    def test_tool_text_contains_no_turkish_specific_characters(self):
        violations = []
        for path in TOOL_ROOT.rglob("*"):
            if not path.is_file() or path.suffix not in TEXT_EXTENSIONS:
                continue
            if "__pycache__" in path.parts:
                continue
            text = path.read_text(errors="replace")
            if any(ord(character) in FORBIDDEN_CODEPOINTS for character in text):
                violations.append(str(path.relative_to(TOOL_ROOT)))
        self.assertEqual(violations, [], f"Turkish text found in tool files: {violations}")


if __name__ == "__main__":
    unittest.main()

