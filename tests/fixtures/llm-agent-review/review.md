## Security review

I found the following issues.

| File | Line | CWE | Description |
|------|------|-----|-------------|
| src/auth.py | 10 | CWE-798 | Hard-coded password |
| src/io.py:55 | | CWE-22 | Path traversal in download |

Prompt tokens: 1,000
Completion tokens: 250
Total cost: $0.02
