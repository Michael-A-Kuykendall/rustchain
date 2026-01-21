# Security Policy

## Supported Versions

We actively support the following versions of RustChain with security updates:

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |

## Reporting a Vulnerability

We take the security of RustChain seriously. If you discover a security vulnerability, please follow these guidelines:

### :lock: Private Disclosure Process

**DO NOT** create a public GitHub issue for security vulnerabilities.

Instead, please report security issues privately using one of these methods:

1. **GitHub Security Advisories (Preferred)**
   - Go to the [Security tab](https://github.com/Michael-A-Kuykendall/rustchain/security) of this repository
   - Click "Report a vulnerability"
   - Fill out the advisory form with details

2. **Direct Email**
   - Send details to: michaelallenkuykendall@gmail.com
   - Include "SECURITY: RustChain" in the subject line

### :memo: What to Include

Please provide the following information in your report:

- **Description**: Clear description of the vulnerability
- **Impact**: What could an attacker accomplish?
- **Reproduction**: Step-by-step instructions to reproduce the issue
- **Environment**:
  - RustChain version
  - Operating system (Windows/macOS/Linux)
  - Rust version
- **Proof of Concept**: Code or logs demonstrating the issue
- **Suggested Fix**: If you have ideas for remediation

### :stopwatch: Response Timeline

We aim to respond to security reports according to the following timeline:

- **Initial Response**: Within 48 hours of report
- **Triage**: Within 7 days - confirm/deny vulnerability
- **Resolution**: Within 30 days for critical issues, 90 days for others
- **Disclosure**: Public disclosure after fix is released and users have time to update

### :warning: Vulnerability Severity Guidelines

We use the following criteria to classify vulnerabilities:

#### Critical
- Remote code execution via mission input
- Memory corruption leading to arbitrary code execution
- Unauthorized command execution

#### High
- Denial of service via crafted input
- Memory exhaustion attacks
- Path traversal leading to arbitrary file access

#### Medium
- Information disclosure
- Panic in safe Rust code
- Resource leaks

#### Low
- Issues requiring local access
- Minor information leaks
- Performance degradation attacks

### :trophy: Recognition

We believe in recognizing security researchers who help keep RustChain secure:

- **Hall of Fame**: Public recognition in our security acknowledgments
- **CVE Assignment**: For qualifying vulnerabilities
- **Acknowledgment**: Credit in release notes

*Note: We currently do not offer monetary bug bounties, but we deeply appreciate responsible disclosure.*

## Security Considerations

### Memory Safety
- RustChain is written in safe Rust by default
- Minimal `unsafe` code, isolated and documented where present
- All inputs are validated before processing

### External Tool Execution
- Tool execution is sandboxed where possible
- Users should review mission files before execution
- LLM-generated commands should be treated as untrusted

### API Keys and Secrets
- API keys are never logged
- Secrets should be passed via environment variables
- Never commit secrets to mission YAML files

### Best Practices for Deployment
- Use RustChain in isolated environments for sensitive workloads
- Regularly update to the latest version
- Review mission files before execution in production
- Implement additional access controls at the infrastructure level

## Security Features

RustChain includes several built-in security features:

- **Memory Safety**: Built with Rust for memory-safe execution
- **Path Sanitization**: Prevents directory traversal attacks
- **Command Validation**: Filters dangerous shell commands
- **Safety Validation**: Pre-execution mission analysis

## Contact

For non-security related issues, please use:
- GitHub Issues: https://github.com/Michael-A-Kuykendall/rustchain/issues

---

*This security policy is effective as of January 2026 and may be updated periodically.*
