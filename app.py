from pathlib import Path
from flask import Flask, render_template, request

from src.analyzer import analyze_events, load_logs

app = Flask(__name__)
BASE_DIR = Path(__file__).resolve().parent
DEFAULT_LOG = BASE_DIR / "data" / "sample_auth.log"


@app.route("/", methods=["GET", "POST"])
def dashboard():
    threshold = int(request.form.get("threshold", 5))
    log_file = DEFAULT_LOG
    events = load_logs(str(log_file))
    report = analyze_events(events, brute_force_threshold=threshold)

    return render_template(
        "dashboard.html",
        report=report,
        events=events[-20:][::-1],
        threshold=threshold,
        log_file=log_file.name,
    )


if __name__ == "__main__":
    app.run(debug=True)
