# AD SecureAudit 🔒

**Advanced Active Directory Security Scanner with Custom Template Support**

Comprehensive security auditing tool for Active Directory environments. Detects misconfigurations, privilege escalation paths, and vulnerabilities using built-in scanners and custom YAML templates.

---

## 🚀 Features

- **ACL Scanner** - Permission misconfigurations, DCSync rights, PrivExchange
- **ADCS Scanner** - Certificate Services vulnerabilities (ESC1-ESC15)
- **GPO Scanner** - Group Policy misconfigurations and weak policies
- **Kerberos Scanner** - AS-REP Roasting, Kerberoasting, delegation abuse
- **Custom Templates** - Nuclei-style YAML templates for flexible checks
- **Attack Path Analysis** - Multi-hop privilege escalation detection
- **Automated Remediation** - PowerShell scripts with rollback support

---

## 📦 Installation

```bash
# Clone repository
git clone https://github.com/yourusername/ad-secureaudit.git
cd ad-secureaudit

# Install dependencies
pip install ldap3 pyyaml

# Optional: Kerberos support (Windows only)
pip install pywin32
```

**Requirements:**
- Python 3.7+
- Domain user credentials (Domain Admin recommended)
- Network access to Domain Controller

---

## 🎯 Quick Start

### Basic Scan

```bash
# Simple scan with credentials
python ad_secaudit.py -d corp.local -u Administrator -p Password123! --ldaps

# Scan with Kerberos (domain-joined machine)
python ad_secaudit.py -d corp.local --kerberos

# Print results to console
python ad_secaudit.py -d corp.local -u admin -p pass --ldaps --print
```

### Scan with Custom Templates

```bash
# Single template
python ad_secaudit.py -d corp.local -u admin -p pass --ldaps -t template.yaml

# Template directory
python ad_secaudit.py -d corp.local -u admin -p pass --ldaps -t /templates/

# Multiple sources
python ad_secaudit.py -d corp.local -u admin -p pass --ldaps -t file1.yaml -t /templates/
```

### Common Options

```bash
# Verbose output
python ad_secaudit.py -d corp.local -u admin -p pass --ldaps -v

# Specific modules only
python ad_secaudit.py -d corp.local -u admin -p pass --ldaps --only adcs,kerberos

# Skip remediation generation
python ad_secaudit.py -d corp.local -u admin -p pass --ldaps --no-remediation
```

---

## 📝 Custom Templates

Write security checks in YAML format:

```yaml
info:
  name: "AS-REP Roastable Accounts"
  author: "Security Team"
  severity: critical
  description: "Accounts without Kerberos pre-authentication"
  attack_vector: "Offline password cracking"
  mitigation: "Enable Kerberos pre-authentication"

ldap:
  search_filter: "(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))"
  attributes:
    - sAMAccountName
    - distinguishedName
    - userAccountControl

detection:
  condition: and
  rules:
    - attribute: userAccountControl
      operator: bitwise_and
      value: 4194304
```

**Supported Operators:**
- `exists`, `not_exists`, `equals`, `contains`, `regex`
- `bitwise_and` (for UAC flags), `greater_than`, `less_than`

See `/templates/` directory for 35+ example templates.

---

## 🔧 Troubleshooting

### No Results Found

```bash
# Use Domain Admin credentials
python ad_secaudit.py -d corp.local -u "CORP\Administrator" -p pass --ldaps

# Test with verbose mode
python ad_secaudit.py -d corp.local -u admin -p pass --ldaps -t template.yaml -v

# Verify test objects exist
Get-ADUser -Filter "Name -like 'test_*'"
```

### Connection Issues

```bash
# Specify DC explicitly
python ad_secaudit.py -d corp.local -s DC01.corp.local -u admin -p pass --ldaps

# Check connectivity
Test-NetConnection -ComputerName DC01.corp.local -Port 636
```

### Template Not Loading

```bash
# Verify YAML syntax
python -c "import yaml; print(yaml.safe_load(open('template.yaml')))"

# Check PyYAML installed
pip install pyyaml
```

For detailed help, run: `python ad_secaudit.py --help`

---

## 🤝 Contributing

Contributions welcome! Submit pull requests with:
- New detection templates
- Bug fixes
- Documentation improvements
- Feature enhancements

---

## ⚠️ Disclaimer

**For authorized security testing only.**

- Use only on networks you own or have permission to test
- Test in lab environments before production
- Review all remediation scripts before execution
- Not responsible for misuse or damage

---

## 📜 License

MIT License - See [LICENSE](LICENSE) file for details.

---

## 🙏 Credits

- **MITRE ATT&CK** - Threat modeling framework
- **Specterops** - ADCS research
- **ldap3** - Python LDAP library
- **Nuclei** - Template system inspiration

---

<div align="center">

**Made for the InfoSec Community** ❤️

[Report Bug](https://github.com/yourusername/ad-secureaudit/issues) · [Request Feature](https://github.com/yourusername/ad-secureaudit/issues)

</div>
