import os
import re
from pathlib import Path

def main():
    root = Path("/Users/paijo/1ai-osint")
    tests = root / "tests"
    
    replacements = [
        (r'([\'"])src\.config([\'"\.])', r'\1src.core.config\2'),
        (r'([\'"])src\.database([\'"\.])', r'\1src.core.database\2'),
        (r'([\'"])src\.models([\'"\.])', r'\1src.core.models\2'),
        (r'([\'"])src\.cache([\'"\.])', r'\1src.core.cache\2'),
        (r'([\'"])src\.rate_limiter([\'"\.])', r'\1src.core.rate_limiter\2'),
        (r'([\'"])src\.cli([\'"\.])', r'\1src.cli.main\2'),
        (r'from src import cli', r'from src.cli import main as cli'),
        (r'import src\.cli\s', r'import src.cli.main as cli '),
        (r'src\.cli\.', r'src.cli.main.')
    ]
    
    for path in tests.rglob("*.py"):
        if path.is_file():
            content = path.read_text(encoding="utf-8")
            new_content = content
            for old, new in replacements:
                new_content = re.sub(old, new, new_content)
            if new_content != content:
                path.write_text(new_content, encoding="utf-8")
                print(f"Fixed mocks in {path.relative_to(root)}")

if __name__ == "__main__":
    main()
