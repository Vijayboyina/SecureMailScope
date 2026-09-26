# 🔐 SecureMailScope

SecureMailScope is a Python-based email security intelligence tool that analyzes publicly available DNS records to assess common email security configurations.

It helps users inspect email authentication mechanisms such as **MX, SPF, DMARC, and DKIM** through a simple security dashboard and command-line interface.

---

## 🚀 Features

* 🔎 Domain-based email security scanning
* 📨 MX record detection
* 🔐 SPF record detection and analysis
* 🛡️ DMARC record detection and policy analysis
* 🔑 DKIM selector detection
* 📊 Custom security score
* ⚠️ Risk-level classification
* 🔎 Security findings
* 💡 Security recommendations
* 🌐 Flask-based web dashboard
* 💻 Command-line scanner
* 🌍 Supports domain and email-address input

---

## 🛡️ Security Checks

### MX

Checks whether the target domain has configured **Mail Exchange (MX)** records used for email delivery.

### SPF

Checks for an SPF TXT record and analyzes its configuration.

The scanner recognizes common SPF policies such as:

* `-all` — strict fail
* `~all` — soft fail
* Other SPF configurations

### DMARC

Checks for a DMARC record at:

```text
_dmarc.<domain>
```

The scanner analyzes the main DMARC policy:

* `p=reject`
* `p=quarantine`
* `p=none`

### DKIM

Checks for publicly discoverable DKIM records using common DKIM selectors.

Users can also provide a specific DKIM selector when known.

Example:

```text
selector1._domainkey.<domain>
```

---

## 📊 Security Scoring

SecureMailScope uses a **custom heuristic scoring system** based on the detected MX, SPF, DMARC, and DKIM configurations.

The current scoring model assigns:

| Security Check | Maximum Points |
| -------------- | -------------: |
| MX             |             15 |
| SPF            |             20 |
| DMARC          |             20 |
| DKIM           |             20 |
| **Total**      |         **75** |

The score is converted to a percentage out of 100.

### Risk Levels

|  Score | Risk Level |
| -----: | ---------- |
| 80–100 | LOW        |
|  50–79 | MEDIUM     |
|   0–49 | HIGH       |

> **Note:** This is a project-defined heuristic and is not an industry-standard security rating.

---

## 🖥️ Dashboard

The Flask dashboard provides:

* Domain scanning
* Email-address domain extraction
* DKIM selector input
* Security score
* Risk level
* MX/SPF/DMARC/DKIM status
* DNS record details
* Security findings
* Security recommendations

---

## 💻 Command-Line Scanner

SecureMailScope can also be used from the command line.

Run:

```bash
python scanner.py
```

The CLI allows users to:

1. Enter a domain
2. Enter an optional DKIM selector
3. Provide a DKIM-Signature header when a selector is not known
4. Scan MX, SPF, DMARC, and DKIM
5. View the security score
6. View findings and recommendations

---

## 🧰 Tech Stack

* **Python**
* **Flask**
* **dnspython**
* **HTML**
* **CSS**
* **DNS**
* **PowerShell / Command Line**

---

## 📁 Project Structure

```text
SecureMailScope/
│
├── app.py
├── scanner.py
├── requirements.txt
├── README.md
├── .gitignore
│
└── templates/
    └── index.html
```

---

## ⚙️ Installation

Clone the repository:

```bash
git clone https://github.com/Vijayboyina/SecureMailScope.git
```

Move into the project directory:

```bash
cd SecureMailScope
```

Create a virtual environment:

```bash
python -m venv venv
```

Activate it on Windows PowerShell:

```powershell
venv\Scripts\Activate.ps1
```

Install dependencies:

```bash
pip install -r requirements.txt
```

---

## ▶️ Running the Dashboard

Start the Flask application:

```bash
python app.py
```

Then open the local address shown by Flask in your browser.

---

## 🔍 Example

A domain scan may produce results such as:

```text
MX       : PASS
SPF      : PASS
DMARC    : PASS
DKIM     : NOT_DETECTED

Security Score : 47/100
Risk Level     : HIGH
```

The tool then provides findings explaining the detected configuration and recommendations for improving email security.

---

## 🎯 Project Objective

The main objective of SecureMailScope is to provide a beginner-friendly way to understand and inspect common email authentication mechanisms.

The project combines **Python programming, DNS analysis, email security concepts, and a web-based security dashboard** into a practical cybersecurity project.

---

## 🔮 Future Enhancements

Planned improvements include:

* 📧 Email-address security analysis
* 📩 Email-header analysis
* 🔍 Authentication-Results parsing
* 🧠 Phishing-indicator detection
* 🔑 Improved DKIM selector discovery
* 📈 Historical scan results
* 📄 Security report generation
* 🔐 Additional email security checks
* 🎨 Further dashboard improvements

---

## ⚠️ Disclaimer

SecureMailScope is intended for **educational, defensive security, and authorized testing purposes**.

The tool analyzes publicly available DNS information and should only be used against domains you are authorized to assess.

---

## 👨‍💻 Author

**Boyina Vijaya Simha Reddy**
**Boddu Vara Prasad Rao**

B.Tech CSE – Cyber Security

St. Ann’s College of Engineering & Technology, Chirala

---

⭐ If you find this project useful, consider giving the repository a star.
