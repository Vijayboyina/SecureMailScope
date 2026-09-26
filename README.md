# 🔐 SecureMailScope

SecureMailScope is a Python-based email security intelligence tool that analyzes publicly available DNS records to assess common email security configurations.

It helps users understand and inspect email authentication mechanisms such as **MX, SPF, DMARC, and DKIM** through a simple security dashboard.

---

## 🚀 Features

- 🔎 Domain-based email security scanning
- 📨 MX record detection
- 🔐 SPF record detection
- 🛡️ DMARC record detection
- 🔑 DKIM selector detection
- 📊 Custom security score
- ⚠️ Risk-level classification
- 🔎 Security findings
- 💡 Security recommendations
- 🌐 Flask-based web dashboard
- 💻 Command-line scanner
- 🧠 DMARC policy analysis

---

## 🛡️ Security Checks

### MX

Checks whether the target domain has configured **Mail Exchange (MX)** records used for email delivery.

### SPF

Checks for an SPF TXT record and analyzes its configuration.

The scanner recognizes common SPF mechanisms such as:

- `-all` — strict fail
- `~all` — soft fail
- Other SPF configurations

### DMARC

Checks for a DMARC record at:

```text
_dmarc.<domain>