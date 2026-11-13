---
description: Turn an llm-assure assessment into a short, client-ready assurance summary
argument-hint: <path to assessment.json> [audience, e.g. CTO or auditor]
---

Write an assurance summary from an llm-assure assessment, using the llm-assure MCP tools.

Input: $ARGUMENTS

1. Call `get_findings` on the assessment file (start with `min_severity` "low").
2. Group findings by OWASP LLM Top 10 category and severity. For each, give the evidence (probe and reply excerpt) and a concrete remediation.
3. State the overall result plainly: pass or fail against the severity gate, the score, and what was not tested.
4. Write it for the audience given (default: an engineering lead), in under one page, and point to the HTML report for full evidence.

Do not soften or omit findings. If the assessment is old or a target changed since, say so.
