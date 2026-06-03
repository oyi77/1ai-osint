import os
import shutil
import re
from pathlib import Path

def main():
    root = Path("/Users/paijo/1ai-osint")
    src = root / "src"
    tests = root / "tests"
    
    # Create new directories
    core_dir = src / "core"
    cli_dir = src / "cli"
    core_dir.mkdir(exist_ok=True)
    cli_dir.mkdir(exist_ok=True)
    
    # 1. Move core files
    core_files = ["config.py", "database.py", "models.py", "cache.py", "rate_limiter.py"]
    for f in core_files:
        src_file = src / f
        if src_file.exists():
            shutil.move(str(src_file), str(core_dir / f))
            print(f"Moved {f} to src/core/")
            
    # Create __init__.py in core
    (core_dir / "__init__.py").touch()
    
    # 2. Refactor CLI (just move it for now to src/cli/main.py)
    cli_file = src / "cli.py"
    if cli_file.exists():
        shutil.move(str(cli_file), str(cli_dir / "main.py"))
        print("Moved cli.py to src/cli/main.py")
        
    (cli_dir / "__init__.py").touch()
    
    # 3. Update imports across all .py files
    replacements = [
        (r"from src\.config import", r"from src.core.config import"),
        (r"import src\.config", r"import src.core.config"),
        (r"from src\.database import", r"from src.core.database import"),
        (r"import src\.database", r"import src.core.database"),
        (r"from src\.models import", r"from src.core.models import"),
        (r"import src\.models", r"import src.core.models"),
        (r"from src\.cache import", r"from src.core.cache import"),
        (r"import src\.cache", r"import src.core.cache"),
        (r"from src\.rate_limiter import", r"from src.core.rate_limiter import"),
        (r"import src\.rate_limiter", r"import src.core.rate_limiter"),
        (r"from src\.cli import", r"from src.cli.main import"),
    ]
    
    def process_dir(directory: Path):
        for path in directory.rglob("*.py"):
            if path.is_file():
                content = path.read_text(encoding="utf-8")
                new_content = content
                for old, new in replacements:
                    new_content = re.sub(old, new, new_content)
                if new_content != content:
                    path.write_text(new_content, encoding="utf-8")
                    print(f"Updated imports in {path.relative_to(root)}")
                    
    process_dir(src)
    process_dir(tests)
    
    # Update pyproject.toml
    pyproject = root / "pyproject.toml"
    if pyproject.exists():
        content = pyproject.read_text(encoding="utf-8")
        new_content = content.replace('"src.cli:app"', '"src.cli.main:app"')
        if new_content != content:
            pyproject.write_text(new_content, encoding="utf-8")
            print("Updated pyproject.toml scripts section.")

if __name__ == "__main__":
    main()
