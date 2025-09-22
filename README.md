# 🤖 AI_CODE_GEN_AGENT

Security-aware AI code generation powered by Claude 3.5 Sonnet (via OpenRouter). Generates production-quality code, explanations, unit tests, and an optional security report.

---

## 📋 Introduction

AI_CODE_GEN_AGENT is a Python tool that turns natural-language problem statements into:
- Secure, production-quality implementations
- Clear algorithmic explanations with time/space complexity
- Optional unit tests and edge cases
- Optional Semgrep security scan and human-readable report

Backed by `anthropic/claude-3.5-sonnet` and strong, OWASP-aligned prompting, it’s designed for developers who want high-quality, secure-by-default code quickly.

---

## 🚀 Installation

### Prerequisites
- Python 3.8+
- OpenRouter API key (`SONNET_API_KEY`) — get one at `https://openrouter.ai/keys`
- (Optional) Semgrep for security scanning: `pip install semgrep`

### Setup
```bash
git clone https://github.com/<your-org>/ai_code_gen_agent.git
cd ai_code_gen_agent

# (optional) create a virtual environment
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate

# install dependencies
pip install -r requirements.txt

# configure your API key
cat > .env << 'EOF'
SONNET_API_KEY=your_openrouter_api_key_here
EOF

# (optional) verify Semgrep
semgrep --version || true
```

---

## 💻 Usage

You can run the interactive CLI or use the library API.

### Command Line (Interactive)
```bash
python /Users/sohailkhan/Documents/ai_code_gen_agent/code_generation_model.py
```
You’ll be prompted to run a basic example, enter a custom problem, or exit. Ensure `SONNET_API_KEY` is set in `.env` or your shell.

### Python Library
```python
from code_generation_model import SOTACodeGenerator

generator = SOTACodeGenerator()  # reads SONNET_API_KEY from .env
result = generator.generate_code(
    problem_description="Implement a binary search algorithm",
    language="python",
    include_tests=True,
    explain_approach=True,
    run_security_scan=True,  # requires semgrep if True
)

print(result["full_response"])     # combined markdown-style output
print(result.get("security_report", ""))
generator.save_results(result)       # writes sota_code_generation_YYYYMMDD_HHMMSS.json
```

Disable security scanning for faster runs:
```python
from code_generation_model import SOTACodeGenerator

generator = SOTACodeGenerator(enable_security_scan=False)
result = generator.generate_code(
    problem_description="Create a REST API endpoint",
    language="python",
    include_tests=False,
    explain_approach=False,
    run_security_scan=False,
)
```

Connectivity test from the CLI:
```bash
python -c "import code_generation_model as m; print(m.test_api_connection())"
```

---

## ✨ Features

- 🧠 **SOTA model**: Uses `anthropic/claude-3.5-sonnet` via OpenRouter
- 🔒 **Security by design**: OWASP-guided prompt; optional Semgrep scan (security-audit, OWASP Top 10, CWE Top 25)
- 🧪 **Unit tests**: Auto-generated tests with edge case coverage
- 📚 **Explanations**: Algorithm approach and time/space complexity
- 🔧 **Multi-language**: Targets Python, JavaScript, Java, Go, and more
- 💾 **Artifacts**: Saves outputs to `sota_code_generation_*.json` with metadata
- ⚙️ **Configurable**: Toggle tests, explanations, target language, and scanning
- 🧰 **CLI + Library**: Use interactively or integrate into Python workflows
- 🛡️ **Resilient**: Clear error handling and optional connectivity check

---

## ⚙️ Configuration

- Environment variables:
  - `SONNET_API_KEY` — OpenRouter API key (required)

- Common parameters:
  - `language` — Target implementation language
  - `include_tests` — Include unit tests
  - `explain_approach` — Include explanation and complexity
  - `run_security_scan` — Run Semgrep on generated code
  - `enable_security_scan` (constructor) — Initialize with Semgrep scanner

---

## 📁 Project Structure

```text
ai_code_gen_agent/
├── code_generation_model.py        # Core code generation module and CLI
├── requirements.txt                # Project dependencies
├── README.md                       # Project documentation
├── .env                            # Local environment variables (not committed)
└── sota_code_generation_*.json     # Generated outputs (timestamped)
```

---

## 🤝 Contributing

Contributions are welcome! To propose changes:
1. Fork the repo and create a feature branch:
```bash
git checkout -b feat/your-feature
```
2. Install dependencies and make changes.
3. Add/update tests and docs where applicable.
4. Open a Pull Request with motivation, changes, and verification steps.

Recommended practices:
- Follow PEP 8, add docstrings and type hints.
- Keep public APIs clear and documented.
- Ensure examples remain runnable.
---

## 🔗 Links

- OpenRouter Keys: `https://openrouter.ai/keys`
- Semgrep: `https://semgrep.dev/`


