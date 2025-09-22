# code_generation.py
import os
import requests
from datetime import datetime
import json
import subprocess
import tempfile
from typing import List, Dict, Any
from dotenv import load_dotenv

load_dotenv()  # Load SONNET_API_KEY from .env


class SemgrepSecurityScanner:
    def __init__(self):
        """Initialize Semgrep scanner"""
        self.semgrep_installed = self._check_semgrep_installation()
        
    def _check_semgrep_installation(self) -> bool:
        """Check if Semgrep is installed"""
        try:
            result = subprocess.run(['semgrep', '--version'], 
                                  capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                print(f"✅ Semgrep found: {result.stdout.strip()}")
                return True
            else:
                print("❌ Semgrep not found. Install with: pip install semgrep")
                return False
        except Exception as e:
            print(f"❌ Semgrep check failed: {str(e)}")
            return False
    
    
    def scan_code(self, code: str, language: str = "python") -> Dict[str, Any]:
        """Scan generated code with Semgrep"""
        if not self.semgrep_installed:
            return {"error": "Semgrep not installed", "vulnerabilities": [], "total_issues": 0}
        
        # Create temporary file with the generated code
        file_extension = self._get_file_extension(language)
        temp_file = None
        
        try:
            with tempfile.NamedTemporaryFile(mode='w', suffix=file_extension, delete=False) as f:
                f.write(code)
                temp_file = f.name
            
            # Run Semgrep scan
            scan_result = self._run_semgrep_scan(temp_file, language)
            
            # Parse and categorize results
            parsed_results = self._parse_semgrep_output(scan_result)
            
            return parsed_results
            
        except Exception as e:
            return {"error": f"Scan failed: {str(e)}", "vulnerabilities": [], "total_issues": 0}
        finally:
            # Clean up temporary file
            if temp_file and os.path.exists(temp_file):
                os.unlink(temp_file)
    
    def _get_file_extension(self, language: str) -> str:
        """Get appropriate file extension for language"""
        extensions = {
            "python": ".py",
            "javascript": ".js",
            "java": ".java",
            "go": ".go",
            "php": ".php",
            "ruby": ".rb",
            "c": ".c",
            "cpp": ".cpp",
            "csharp": ".cs"
        }
        return extensions.get(language.lower(), ".txt")
    
    def _run_semgrep_scan(self, filepath: str, language: str) -> Dict:
        """Run Semgrep scan on the file"""
        # Semgrep rulesets to use
        rulesets = [
            "p/security-audit",  # General security issues
            "p/owasp-top-ten",   # OWASP Top 10
            "p/cwe-top-25",      # CWE Top 25
        ]
        
        # Add language-specific rulesets
        if language.lower() == "python":
            rulesets.extend(["p/python", "p/bandit"])
        elif language.lower() == "javascript":
            rulesets.extend(["p/javascript", "p/nodejs"])
        elif language.lower() == "java":
            rulesets.append("p/java")
        
        # Build semgrep command
        cmd = [
            "semgrep",
            "--config=" + ",".join(rulesets),
            "--json",
            "--severity=ERROR",  # Focus on high-severity issues
            "--severity=WARNING",
            filepath
        ]
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            if result.returncode in [0, 1]:  # 0 = no findings, 1 = findings found
                return json.loads(result.stdout)
            else:
                return {"error": f"Semgrep failed: {result.stderr}"}
        except subprocess.TimeoutExpired:
            return {"error": "Semgrep scan timeout"}
        except json.JSONDecodeError:
            return {"error": "Failed to parse Semgrep output"}
    
    def _parse_semgrep_output(self, semgrep_output: Dict) -> Dict[str, Any]:
        """Parse and categorize Semgrep output"""
        if "error" in semgrep_output:
            return semgrep_output
        
        results = semgrep_output.get("results", [])
        
        # Categorize vulnerabilities by severity and type
        vulnerabilities = {
            "critical": [],
            "high": [],
            "medium": [],
            "low": [],
            "total_count": len(results)
        }
        
        vulnerability_types = {}
        
        for result in results:
            severity = result.get("extra", {}).get("severity", "UNKNOWN").lower()
            if severity == "error":
                severity = "high"
            elif severity == "warning":
                severity = "medium"
            elif severity == "info":
                severity = "low"
            
            # Create vulnerability record
            vuln = {
                "rule_id": result.get("check_id", "unknown"),
                "message": result.get("extra", {}).get("message", "No description"),
                "line": result.get("start", {}).get("line", 0),
                "column": result.get("start", {}).get("col", 0),
                "severity": severity,
                "fix_suggestion": result.get("extra", {}).get("fix", "No fix suggestion")
            }
            
            # Add to appropriate severity category
            if severity in vulnerabilities:
                vulnerabilities[severity].append(vuln)
            
            # Track vulnerability types
            vuln_type = result.get("check_id", "").split(".")[-1]
            vulnerability_types[vuln_type] = vulnerability_types.get(vuln_type, 0) + 1
        
        return {
            "vulnerabilities": vulnerabilities,
            "vulnerability_types": vulnerability_types,
            "scan_status": "completed",
            "total_issues": len(results)
        }
    
    def generate_security_report(self, scan_results: Dict) -> str:
        """Generate human-readable security report"""
        if "error" in scan_results:
            return f"❌ Security scan failed: {scan_results['error']}"
        
        vulnerabilities = scan_results.get("vulnerabilities", {})
        total_issues = scan_results.get("total_issues", 0)
        
        if total_issues == 0:
            return "✅ SECURITY SCAN PASSED: No vulnerabilities detected!"
        
        report = f"SECURITY SCAN RESULTS\n"
        report += f"=" * 40 + "\n"
        report += f"Total Issues Found: {total_issues}\n\n"
        
        # Severity breakdown
        for severity in ["critical", "high", "medium", "low"]:
            count = len(vulnerabilities.get(severity, []))
            if count > 0:
                icon = "🚨" if severity == "critical" else "⚠️" if severity == "high" else "⚡" if severity == "medium" else "ℹ️"
                report += f"{icon} {severity.upper()}: {count} issues\n"
        
        report += "\n" + "=" * 40 + "\n"
        
        # Detailed issues (show only critical and high for brevity)
        for severity in ["critical", "high"]:
            issues = vulnerabilities.get(severity, [])
            if issues:
                report += f"\n{severity.upper()} SEVERITY ISSUES:\n"
                report += "-" * 20 + "\n"
                
                for i, issue in enumerate(issues, 1):
                    report += f"{i}. {issue['message']}\n"
                    report += f"   Rule: {issue['rule_id']}\n"
                    report += f"   Location: Line {issue['line']}, Column {issue['column']}\n"
                    if issue['fix_suggestion'] != "No fix suggestion":
                        report += f"   Fix: {issue['fix_suggestion']}\n"
                    report += "\n"
        
        return report


class SOTACodeGenerator:
    def __init__(self, api_key: str = None, enable_security_scan: bool = True):
        """Initialize the SOTA code generation model (Claude 3.5 Sonnet via OpenRouter)"""
        self.api_key = api_key or os.getenv("SONNET_API_KEY")
        if not self.api_key:
            raise ValueError("❌ SONNET_API_KEY not found. Please set it in your .env or pass explicitly.")

        self.url = "https://openrouter.ai/api/v1/chat/completions"
        self.model_name = "anthropic/claude-3.5-sonnet"
        self.security_scanner = SemgrepSecurityScanner() if enable_security_scan else None

        print(f"✅ Initialized Code Generation Model: {self.model_name}")
        
        if enable_security_scan:
            print("Security scanning enabled with Semgrep")

    def generate_code(self, 
                      problem_description: str, 
                      language: str = "python",
                      include_tests: bool = True,
                      explain_approach: bool = True,
                      run_security_scan: bool = True) -> Dict[str, Any]:
        """Generate code using Claude 3.5 Sonnet via OpenRouter with optional security scanning"""

        prompt = self._build_academic_prompt(problem_description, language, include_tests, explain_approach)

        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }

        payload = {
            "model": self.model_name,
            "messages": [
                {
                    "role": "system",
                    "content": (
                        "You are a security-aware software engineer. Generate production-quality code that is secure and vulnerability-free.\n"
                        "Your output must strictly follow the CORE SECURITY RULES and VULNERABILITY CHECKLIST below.\n"
                        "CORE SECURITY RULES:\n"
                        "- Validate and sanitize all inputs\n"
                        "- No hardcoded secrets or credentials\n"
                        "- Use parameterized queries for databases\n"
                        "- Handle errors securely without exposing sensitive info\n"
                        "- Apply OWASP security best practices\n"
                        "VULNERABILITY CHECKLIST (must verify and address in your solution):\n"
                        "- SQL Injection (use prepared statements/ORM safety)\n"
                        "- Cross-Site Scripting (XSS) — escape/encode output\n"
                        "- Cross-Site Request Forgery (CSRF) — tokens, same-site cookies\n"
                        "- Authentication & Authorization — enforce strong controls, least privilege\n"
                        "- Sensitive Data Exposure — encrypt data at rest & in transit, use TLS/HTTPS\n"
                        "- Security Misconfiguration — apply secure defaults, avoid debug modes\n"
                        "- Server-Side Request Forgery (SSRF) — validate/whitelist URLs\n"
                        "- Insecure Deserialization — avoid unsafe deserialization\n"
                        "- Broken Access Control — verify role/permissions before actions\n"
                        "- Security Logging & Monitoring — log securely, avoid sensitive data leaks\n"
                    ),
                },
                {"role": "user", "content": prompt}
            ],
            "temperature": 0.1,
            "max_tokens": 4000
        }

        try:
            response = requests.post(self.url, headers=headers, json=payload, timeout=60)
            response.raise_for_status()
            data = response.json()
            generated_content = data["choices"][0]["message"]["content"]

            result = self._parse_generated_response(generated_content)
            result.update({
                "model_used": self.model_name,
                "timestamp": datetime.now().isoformat(),
                "problem_description": problem_description,
                "language": language
            })
            
            # Run security scan if enabled and no errors in generation
            if run_security_scan and self.security_scanner and "error" not in result:
                main_code = result.get("main_code", "")
                if main_code:
                    print("\n🔍 Running post-generation security scan...")
                    scan_results = self.security_scanner.scan_code(main_code, language)
                    security_report = self.security_scanner.generate_security_report(scan_results)
                    
                    # Add security scan results to the response
                    result.update({
                        "security_scan_results": scan_results,
                        "security_report": security_report,
                        "security_scan_passed": scan_results.get("total_issues", 0) == 0,
                        "has_critical_issues": len(scan_results.get("vulnerabilities", {}).get("critical", [])) > 0
                    })
                    
                    print("\n" + security_report)
                    
                    # Warn about critical issues
                    if result.get("has_critical_issues", False):
                        print("🚨 WARNING: Critical security vulnerabilities detected!")
                        print("⚠️ This code should NOT be deployed without fixing these issues!")
            
            return result

        except Exception as e:
            return {
                "error": f"Code generation failed: {str(e)}",
                "model_used": self.model_name,
                "timestamp": datetime.now().isoformat()
            }

    def _build_academic_prompt(self, problem: str, language: str,
                              include_tests: bool, explain_approach: bool) -> str:
        """Build a clear, security-aware, and strictly structured prompt.

        Note: Section headers must match the parser expectations exactly.
        """

        parts = []

        parts.append(
            f"""
ACADEMIC CODE GENERATION TASK

PROBLEM STATEMENT:
{problem}

TARGET LANGUAGE: {language}

REQUIREMENTS:
- Provide clean, production-quality code following best practices
- Security by design (no hardcoded secrets; avoid eval/exec; parameterize queries)
- Validate and sanitize inputs; handle errors without leaking sensitive info
- Keep the implementation runnable and self-contained
"""
        )

        if explain_approach:
            parts.append(
                """
EXPLANATION REQUIREMENTS:
- Summarize the algorithm and key design decisions
- Explain why the approach is safe and robust
- Include time and space complexity
"""
            )

        if include_tests:
            parts.append(
                """
TESTING REQUIREMENTS:
- Provide runnable unit tests
- Cover edge cases and failure modes
"""
            )

        parts.append(
            f"""
OUTPUT FORMAT (use these exact sections):

## Algorithm Approach
[Explain your approach and reasoning concisely]

## Security Analysis
[Identify possible vulnerabilities for this problem and how you will mitigate them]

## Secure Implementation
```{language}
[Provide the secure, production-quality implementation here]
```

## Unit Tests
```{language}
[Comprehensive tests; if tests are not requested, you may leave this empty]
```

## Edge Cases Considered
- [List key edge cases handled]
"""
        )

        return "\n".join(s.strip() for s in parts if s)

    def _parse_generated_response(self, content: str) -> Dict[str, Any]:
        """Parse structured response from the model"""
        result = {
            "full_response": content,
            "approach_explanation": "",
            "security_analysis": "",
            "main_code": "",
            "test_code": "",
            "edge_cases": ""
        }
        
        sections = content.split("##")
        for section in sections:
            section = section.strip()
            if section.startswith("Algorithm Approach"):
                result["approach_explanation"] = section.replace("Algorithm Approach", "").strip()
            elif section.startswith("Security Analysis"):
                result["security_analysis"] = section.replace("Security Analysis", "").strip()
            elif "```" in section and ("Implementation" in section or "Secure Implementation" in section):
                code_blocks = section.split("```")
                if len(code_blocks) >= 2:
                    # Remove language identifier if present
                    code = code_blocks[1].strip()
                    if code.startswith(('python', 'java', 'javascript', 'go', 'php', 'ruby', 'c', 'cpp', 'csharp')):
                        code = '\n'.join(code.split('\n')[1:])
                    result["main_code"] = code.strip()
            elif "```" in section and "Unit Tests" in section:
                code_blocks = section.split("```")
                if len(code_blocks) >= 2:
                    # Remove language identifier if present
                    code = code_blocks[1].strip()
                    if code.startswith(('python', 'java', 'javascript', 'go', 'php', 'ruby', 'c', 'cpp', 'csharp')):
                        code = '\n'.join(code.split('\n')[1:])
                    result["test_code"] = code.strip()
            elif section.startswith("Edge Cases"):
                result["edge_cases"] = section.replace("Edge Cases Considered", "").strip()
        
        return result

    def save_results(self, results: Dict[str, Any], filename: str = None) -> str:
        """Save generation results to JSON file"""
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"sota_code_generation_{timestamp}.json"
        
        with open(filename, 'w') as f:
            json.dump(results, f, indent=2, ensure_ascii=False)
        
        print(f"💾 Results saved to: {filename}")
        return filename


# Example usage functions
def example_basic_usage():
    """Basic example of using the SOTA code generator with security scanning"""
    
    # Initialize the generator with security scanning enabled
    generator = SOTACodeGenerator(enable_security_scan=True)
    
    # Example problem
    problem = """
    Implement a function that finds the longest palindromic substring in a given string.
    The function should be efficient and handle edge cases like empty strings and single characters.
    """
    
    # Generate solution
    print("🚀 Generating solution with SOTA model...")
    result = generator.generate_code(
        problem_description=problem,
        language="python",
        include_tests=True,
        explain_approach=True,
        run_security_scan=True
    )
    
    # Display results
    if "error" not in result:
        print("\n" + "="*50)
        print("📊 SOTA CODE GENERATION RESULTS")
        print("="*50)
        print(f"Model: {result['model_used']}")
        print(f"Generated at: {result['timestamp']}")
        
        # Security status
        if 'security_scan_passed' in result:
            status = "✅ SECURE" if result['security_scan_passed'] else "❌ VULNERABLE"
            print(f"Security Status: {status}")
        
        print("\n" + result['full_response'])
        
        # Save results
        filename = generator.save_results(result)
        print(f"\n✅ Complete results saved to: {filename}")
    else:
        print(f"❌ Error: {result['error']}")


def test_api_connection():
    """Test if the API connection works"""
    try:
        generator = SOTACodeGenerator(enable_security_scan=False)  # Disable scan for quick test
        
        # Simple test problem
        test_problem = "Write a function to add two numbers and return the result."
        
        print("🧪 Testing API connection...")
        result = generator.generate_code(
            problem_description=test_problem,
            language="python",
            include_tests=False,
            explain_approach=False,
            run_security_scan=False
        )
        
        if "error" not in result:
            print("✅ API connection successful!")
            print("Sample response:")
            print(result['full_response'][:200] + "...")
            return True
        else:
            print(f"❌ API test failed: {result['error']}")
            return False
            
    except Exception as e:
        print(f"❌ Connection test failed: {str(e)}")
        return False


if __name__ == "__main__":
    print("🎓 SOTA Code Generation Model - Claude 3.5 Sonnet with Semgrep Security Scanning")
    print("=" * 80)
    
    # First test the connection
    if test_api_connection():
        print("\n Choose an option:")
        print("1. Run basic example (palindrome problem)")
        print("2. Enter custom problem")
        print("3. Exit")
        
        choice = input("\nEnter your choice (1-3): ").strip()
        
        if choice == "1":
            example_basic_usage()
        elif choice == "2":
            generator = SOTACodeGenerator()
            custom_problem = input("\n📝 Enter your coding problem: ")
            language = input("🔧 Programming language (default: python): ").strip() or "python"
            enable_scan = input("🔒 Enable security scanning? (Y/n): ").strip().lower() != 'n'
            
            print(f"\n🚀 Generating solution for your problem...")
            result = generator.generate_code(
                problem_description=custom_problem,
                language=language,
                include_tests=True,
                explain_approach=True,
                run_security_scan=enable_scan
            )
            
            if "error" not in result:
                print("\n" + "="*50)
                print("📊 GENERATED SOLUTION")
                print("="*50)
                
                # Security status
                if 'security_scan_passed' in result:
                    status = "✅ SECURE" if result['security_scan_passed'] else "❌ VULNERABLE"
                    print(f"Security Status: {status}")
                    if result.get("has_critical_issues", False):
                        print("🚨 CRITICAL VULNERABILITIES FOUND")
                
                print("\n" + result['full_response'])
                
                # Save results
                filename = generator.save_results(result)
                print(f"\n✅ Results saved to: {filename}")
            else:
                print(f"❌ Error: {result['error']}")
                
        elif choice == "3":
            print("👋 Goodbye!")
        else:
            print("❌ Invalid choice")
    else:
        print("\n🔧 Please check your API key and try again.")
        print("💡 Make sure SONNET_API_KEY is set in your .env file")