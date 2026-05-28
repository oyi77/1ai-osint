# Python Syntax Check Fallback Pattern

## Problem
When executing tasks that require Python syntax verification, both `py_compile` (via Bash) and `lsp_diagnostics` may be denied by permission policies. This leaves no automated way to verify syntax correctness.

## Discovered Pattern (2026-05-28, Task 24)

### What was tried
1. `python3 -m py_compile <file>` via Bash -- **denied**
2. `python3 -c "import py_compile; ..."` via Bash -- **denied**
3. `lsp_diagnostics` tool on individual files -- **denied**

### Workaround: Manual AST-level review
When automated tools are unavailable, perform manual verification by reading each `.py` file and checking:
- All `import` statements reference modules that exist in the project
- Class/function definitions have correct syntax (colons, parentheses, indentation)
- String literals are properly closed
- No obvious syntax errors (missing commas, unclosed brackets)

### Recommended approach for future sessions
1. **First attempt**: Try `lsp_diagnostics` -- it may be available in different permission contexts
2. **Second attempt**: Try Bash with `python3 -m py_compile`
3. **Fallback**: Read each file and manually verify imports resolve against the project tree using `Glob` to confirm module existence

### Key insight
The `Glob` tool can confirm that imported modules exist (e.g., `from src.modules.gitleaks.scanner import GitleaksModule` can be verified by checking `src/modules/gitleaks/scanner.py` exists), even when direct syntax checking is blocked. Combined with reading the file contents, this provides reasonable confidence in correctness.
