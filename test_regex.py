#!/usr/bin/env python3
import re

pattern = r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\b\na-z]{2,}\b"
print("Pattern:", repr(pattern))

# Fix the pattern
fixed_pattern = r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\b\na-z]{2,}\b"
print("Fixed pattern:", repr(fixed_pattern))

# Even better - use a simpler pattern
simple_email = r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\b\na-z]{2,}"
print("Simple:", repr(simple_email))

# The issue is \\b in raw string becomes literal \b which is backspace, not word boundary
# Word boundary in regex is \b not \\b in raw strings

print("\nCorrect patterns should be:")
print(r"email: \b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\b\na-z]{2,}\b")
print("But this has \\b which is backspace character")
print(r"Correct: \b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\b\na-z]{2,}\b (word boundary)")
