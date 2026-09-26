from flask import Flask, render_template, request
from scanner import scan_domain, calculate_score, generate_findings, generate_recommendations

app = Flask(__name__)


@app.route("/", methods=["GET", "POST"])
def index():
    result = None
    security = None
    findings = []
    recommendations = []

    if request.method == "POST":
        input_value = request.form.get("domain", "").strip()
        selector = request.form.get("selector", "").strip()

        if "@" in input_value:
            domain = input_value.split("@")[-1].strip().lower()
        else:
            domain = input_value.lower()

        if selector == "":
            selector = None

        if domain:
            result = scan_domain(domain, selector)
            security = calculate_score(result)
            findings = generate_findings(result)
            recommendations = generate_recommendations(result)

    return render_template(
        "index.html",
        result=result,
        security=security,
        findings=findings,
        recommendations=recommendations
    )


if __name__ == "__main__":
    app.run(debug=True)