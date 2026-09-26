import dns.resolver
resolver = dns.resolver.Resolver()
resolver.nameservers = ["8.8.8.8", "1.1.1.1"]
resolver.timeout = 3
resolver.lifetime = 5

def get_records(domain, record_type):
    try:
        answers = dns.resolver.resolve(domain, record_type)
        return [str(answer) for answer in answers]
    except Exception:
        return []


def check_mx(domain):
    records = get_records(domain, "MX")

    return {
        "status": "PASS" if records else "FAIL",
        "records": records
    }


def check_spf(domain):
    try:
        answers = resolver.resolve(domain, "TXT")

        spf_records = []

        for record in answers:
            text = record.to_text().strip('"')

            if text.startswith("v=spf1"):
                spf_records.append(text)

        if spf_records:
            return {
                "status": "PASS",
                "records": spf_records
            }

        return {
            "status": "FAIL",
            "records": []
        }

    except Exception as e:
        return {
            "status": "ERROR",
            "message": str(e)
        }


def check_dmarc(domain):
    records = get_records(f"_dmarc.{domain}", "TXT")

    dmarc_records = [
        record for record in records
        if "v=dmarc1" in record.lower()
    ]

    return {
        "status": "PASS" if dmarc_records else "FAIL",
        "records": dmarc_records
    }

import re


def extract_dkim_selector(dkim_header):
    if not dkim_header:
        return None

    match = re.search(r"(?:^|[;\s])s=([^;\s]+)", dkim_header)

    if match:
        return match.group(1)

    return None
def check_dkim(domain, selector=None):
    selectors = []

    if selector:
        selectors.append(selector)
    else:
        selectors.extend([
            "default",
            "selector1",
            "selector2",
            "google",
            "k1",
            "dkim",
            "mail"
        ])

    selectors = list(dict.fromkeys(selectors))

    found_records = []
    failed_lookups = []

    for selector_name in selectors:
        dkim_domain = f"{selector_name}._domainkey.{domain}"

        try:
            answers = resolver.resolve(dkim_domain, "TXT")

            for record in answers:
                text = record.to_text().strip('"')

                if "v=DKIM1" in text or "p=" in text:
                    found_records.append({
                        "selector": selector_name,
                        "record": text
                    })

        except dns.resolver.NXDOMAIN:
            failed_lookups.append(selector_name)

        except dns.resolver.NoAnswer:
            failed_lookups.append(selector_name)

        except dns.resolver.Timeout:
            return {
                "status": "ERROR",
                "records": [],
                "message": "DNS lookup timed out while checking DKIM."
            }

        except Exception:
            failed_lookups.append(selector_name)

    if found_records:
        return {
            "status": "PASS",
            "records": found_records
        }

    return {
        "status": "NOT_DETECTED",
        "records": []
    }

def scan_domain(domain, selector=None):

    results = {
        "domain": domain,
        "MX": check_mx(domain),
        "SPF": check_spf(domain),
        "DMARC": check_dmarc(domain),
        "DKIM": check_dkim(domain, selector)
    }

    return results



def calculate_score(result):
    score = 0
    max_score = 75

    # MX: 15 points
    if result["MX"]["status"] == "PASS":
        score += 15

    # SPF: 20 points
    if result["SPF"]["status"] == "PASS":
        spf_records = result["SPF"]["records"]

        if spf_records:
            spf_record = spf_records[0]

            if "-all" in spf_record:
                score += 20
            elif "~all" in spf_record:
                score += 15
            else:
                score += 10

    # DMARC: 20 points
    if result["DMARC"]["status"] == "PASS":
        dmarc_records = result["DMARC"]["records"]

        if dmarc_records:
            dmarc_record = dmarc_records[0]
            policy = extract_dmarc_policy(dmarc_record)

            if policy == "reject":
                score += 20
            elif policy == "quarantine":
                score += 15
            elif policy == "none":
                score += 10
            else:
                score += 5

    # DKIM: 20 points
    if result["DKIM"]["status"] == "PASS":
        score += 20

    # Convert 75-point score to 100
    percentage = round((score / max_score) * 100)

    # Risk classification
    if percentage >= 80:
        risk = "LOW"
    elif percentage >= 50:
        risk = "MEDIUM"
    else:
        risk = "HIGH"

    return {
        "score": percentage,
        "risk": risk
    }
    score = 0

    if result["MX"]["status"] == "PASS":
        score += 25

    if result["SPF"]["status"] == "PASS":
        score += 25

    if result["DMARC"]["status"] == "PASS":
        score += 25

    if result["DKIM"]["status"] == "PASS":
        score += 25

    if score >= 75:
        risk = "LOW"
    elif score >= 50:
        risk = "MEDIUM"
    else:
        risk = "HIGH"

    return {
        "score": score,
        "risk": risk
    }    
def extract_dmarc_policy(record):
    if not record:
        return None

    parts = record.split(";")

    for part in parts:
        part = part.strip()

        if part.startswith("p="):
            return part.split("=", 1)[1].lower()

    return None
def generate_findings(result):
    findings = []

    # MX
    if result["MX"]["status"] == "PASS":
        findings.append(
            "MX record detected: domain has a configured mail server."
        )
    else:
        findings.append(
            "MX record not detected: domain may not have a properly configured mail server."
        )

    # SPF
    if result["SPF"]["status"] == "PASS":
        spf_record = result["SPF"]["records"][0]

        if "-all" in spf_record:
            findings.append(
                "SPF is configured with a strict '-all' policy."
            )
        elif "~all" in spf_record:
            findings.append(
                "SPF is configured, but uses '~all' (soft fail)."
            )
        else:
            findings.append(
                "SPF is configured."
            )
    else:
        findings.append(
            "SPF record not detected: email spoofing protection may be weaker."
        )

    # DMARC
    if result["DMARC"]["status"] == "PASS":
        dmarc_record = result["DMARC"]["records"][0]

        policy = extract_dmarc_policy(dmarc_record)

        if policy == "reject":
            findings.append(
                "DMARC policy is 'reject', providing strong spoofing protection."
            )
        elif policy == "quarantine":
            findings.append(
                "DMARC policy is 'quarantine'."
            )
        elif policy == "none":
            findings.append(
                "DMARC is configured with policy 'none' (monitoring mode)."
            )
        else:
            findings.append(
                "DMARC record detected."
            )
    else:
        findings.append(
            "DMARC record not detected: domain lacks a visible DMARC policy."
        )

    # DKIM
    if result["DKIM"]["status"] == "PASS":
        findings.append(
            "DKIM record detected."
        )
    else:
        findings.append(
            "DKIM selector was not discovered using the scanner's current selector list."
        )

    return findings
def generate_recommendations(result):
    recommendations = []

    # MX
    if result["MX"]["status"] != "PASS":
        recommendations.append(
            "Configure a valid MX record for reliable email delivery."
        )

    # SPF
    if result["SPF"]["status"] != "PASS":
        recommendations.append(
            "Configure an SPF record to help prevent unauthorized email senders."
        )
    else:
        spf_record = result["SPF"]["records"][0]

        if "~all" in spf_record:
            recommendations.append(
                "Consider reviewing the SPF policy and using '-all' when all legitimate senders are correctly defined."
            )

    # DMARC
    if result["DMARC"]["status"] != "PASS":
        recommendations.append(
            "Configure a DMARC record to protect the domain against email spoofing."
        )
    else:
        dmarc_record = result["DMARC"]["records"][0]

        policy = extract_dmarc_policy(dmarc_record)

        if policy == "none":
            recommendations.append(
                "Consider moving DMARC from monitoring mode to quarantine or reject after validating legitimate email sources."
            )
        elif policy == "quarantine":
            recommendations.append(
                "Consider using DMARC 'reject' after validating legitimate email sources."
            )

    # DKIM
    if result["DKIM"]["status"] != "PASS":
        recommendations.append(
            "Configure DKIM and ensure the required selector is publicly discoverable."
        )

    if not recommendations:
        recommendations.append(
            "No major recommendations based on the current checks."
        )

    return recommendations

if __name__ == "__main__":
    domain = input("Enter domain to scan: ").strip()

    selector = input("Enter DKIM selector (optional): ").strip()

    if selector == "":
        dkim_header = input("Paste DKIM-Signature header (optional): ").strip()

        if dkim_header:
            selector = extract_dkim_selector(dkim_header)
        else:
            selector = None

    result = scan_domain(domain, selector)
    security = calculate_score(result)
    findings = generate_findings(result)
    recommendations = generate_recommendations(result)

    print("\n========================================")
    print("         SecureMailScope")
    print("       Email Security Scanner")
    print("========================================")

    print(f"\nDomain: {domain}\n")

    print(f"[+] MX       : {result['MX']['status']}")
    print(f"[+] SPF      : {result['SPF']['status']}")
    print(f"[+] DMARC    : {result['DMARC']['status']}")
    print(f"[!] DKIM     : {result['DKIM']['status']}")

    print("\n----------------------------------------")
    print(f"Security Score : {security['score']}/100")
    print(f"Risk Level     : {security['risk']}")
    print("----------------------------------------")

    print("\nSecurity Findings:")
    for finding in findings:
        print(f"- {finding}")

    print("\nRecommendations:")
    for recommendation in recommendations:
        print(f"- {recommendation}")

