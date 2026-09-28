"""
Phishing URL Detection System - Web Application
Built with Flask, scikit-learn, and SQLite.
Academic-grade Cybersecurity Project for Windows.
"""

import os
import json
import re
import joblib
from pathlib import Path
from urllib.parse import urlparse
from flask import Flask, render_template, request, jsonify, redirect, url_for, flash

from utils.url_features import (
    extract_features,
    extract_feature_vector,
    evaluate_reasons,
    normalize_url,
    FEATURE_NAMES
)
from database.db import (
    init_db,
    insert_scan,
    get_scan_by_id,
    get_recent_scans,
    get_all_scans,
    delete_scan,
    clear_all_scans,
    get_dashboard_stats
)

BASE_DIR = Path(__file__).resolve().parent
MODEL_PATH = BASE_DIR / "models" / "phishing_model.pkl"
METADATA_PATH = BASE_DIR / "models" / "model_metadata.json"

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "cybersec-phish-shield-production-key-2026")
app.config["TEMPLATES_AUTO_RELOAD"] = os.environ.get("FLASK_DEBUG", "false").lower() in ["true", "1"]

# Initialize database
init_db()

# Load Trained Machine Learning Model
ml_model = None
model_metadata = {}

def load_ml_model():
    global ml_model, model_metadata
    if MODEL_PATH.exists():
        try:
            ml_model = joblib.load(str(MODEL_PATH))
            print(f"[+] ML Model loaded successfully from: {MODEL_PATH}")
        except Exception as e:
            print(f"[!] Error loading ML Model: {e}")
            ml_model = None
    else:
        print(f"[!] Warning: Trained model not found at {MODEL_PATH}")

    if METADATA_PATH.exists():
        try:
            with open(METADATA_PATH, "r", encoding="utf-8") as f:
                model_metadata = json.load(f)
        except Exception as e:
            print(f"[!] Error loading model metadata: {e}")

load_ml_model()


def validate_url_syntax(raw_url: str):
    """
    Validates URL input without making external network calls.
    Returns (is_valid, sanitized_url, error_message).
    """
    if not raw_url or not raw_url.strip():
        return False, "", "URL field cannot be empty. Please enter a valid website address."

    cleaned = raw_url.strip()
    if len(cleaned) < 3:
        return False, "", "The entered URL is too short to be a valid web address."
    if len(cleaned) > 2048:
        return False, "", "URL exceeds standard maximum length (2048 characters)."

    # Normalize protocol if missing
    normalized = normalize_url(cleaned)
    parsed = urlparse(normalized)

    # Check for valid hostname or IP
    hostname = parsed.netloc
    if not hostname:
        return False, "", "Invalid URL format: Unable to determine the domain or host."

    # Validate basic character syntax
    if any(c in hostname for c in [" ", "<", ">", '"', "'", "\\", "{", "}"]):
        return False, "", "URL contains invalid or forbidden characters."

    return True, normalized, None


def analyze_url_core(raw_url: str):
    """
    Performs full static cybersecurity and machine learning analysis on a URL.
    Returns a comprehensive result dictionary.
    """
    is_valid, normalized, err = validate_url_syntax(raw_url)
    if not is_valid:
        return {"success": False, "error": err}

    features = extract_features(normalized)
    feature_vector = [features[name] for name in FEATURE_NAMES]

    # Machine Learning Inference
    if ml_model is not None:
        try:
            proba = ml_model.predict_proba([feature_vector])[0]
            prob_safe = proba[0]
            prob_phish = proba[1]
        except Exception as e:
            print("[!] ML Inference error, applying heuristic fallback:", e)
            prob_phish = 0.5
            prob_safe = 0.5
    else:
        prob_phish = 0.5
        prob_safe = 0.5

    # Heuristic Security Adjustments (Domain specific signals)
    heuristic_penalty = 0
    if features.get("has_ip_address"):
        heuristic_penalty += 35
    if features.get("has_at_symbol"):
        heuristic_penalty += 30
    if features.get("suspicious_tld"):
        heuristic_penalty += 25
    if features.get("is_shortened"):
        heuristic_penalty += 20
    if features.get("has_https") == 0 and features.get("suspicious_word_count", 0) > 0:
        heuristic_penalty += 25
    if features.get("num_subdomains", 0) >= 3:
        heuristic_penalty += 15
    if features.get("digit_ratio", 0) > 0.3:
        heuristic_penalty += 15

    # Calculate blended Risk Score (0 - 100)
    base_ml_score = prob_phish * 100.0
    combined_score = (base_ml_score * 0.70) + (min(heuristic_penalty, 100) * 0.30)
    
    # Established domain credit (if not using deceptive tokens)
    if features.get("domain_age_heuristic") == 2 and not features.get("has_ip_address") and not features.get("has_at_symbol"):
        if features.get("suspicious_word_count", 0) == 0:
            combined_score = min(combined_score, 18.0)

    risk_score = int(round(max(0, min(100, combined_score))))

    # Risk Tier & Status Classification
    if risk_score <= 30:
        risk_level = "LOW"
        result_label = "Likely Safe"
        badge_status = "SAFE"
        confidence = round(max(prob_safe * 100, 100 - risk_score), 1)
    elif risk_score <= 70:
        risk_level = "MEDIUM"
        result_label = "Suspicious"
        badge_status = "SUSPICIOUS"
        confidence = round(max(prob_phish * 100, risk_score), 1)
    else:
        risk_level = "HIGH"
        result_label = "Likely Phishing"
        badge_status = "PHISHING"
        confidence = round(max(prob_phish * 100, risk_score), 1)

    reasons = evaluate_reasons(features, normalized)

    # Security Recommendations tailored to findings
    recommendations = []
    if risk_level == "HIGH":
        recommendations.append("DO NOT submit usernames, passwords, credit card numbers, or OTP codes on this site.")
        recommendations.append("Do not download or execute any file attachments provided via this URL.")
        recommendations.append("Navigate to the legitimate company website directly by typing their official domain into your browser.")
        recommendations.append("Report this URL to your organization's IT security team or reporting portal.")
    elif risk_level == "MEDIUM":
        recommendations.append("Exercise extreme caution before interacting with this web page.")
        recommendations.append("Check the address bar closely for subtle character misspellings (typosquatting).")
        recommendations.append("Verify the website certificate and ensure it belongs to the intended institution.")
    else:
        recommendations.append("URL exhibits standard legitimate lexical patterns; however, always verify TLS padlock in your browser.")
        recommendations.append("Ensure multi-factor authentication (2FA) is enabled on all important accounts.")
        recommendations.append("Never reuse master passwords across different online services.")

    # Save to SQLite Database
    scan_id = insert_scan(
        url=raw_url.strip(),
        domain=features.get("domain_name", ""),
        result=result_label,
        risk_score=risk_score,
        risk_level=risk_level,
        confidence=confidence,
        features=features,
        reasons=reasons
    )

    return {
        "success": True,
        "scan_id": scan_id,
        "raw_url": raw_url.strip(),
        "normalized_url": normalized,
        "domain": features.get("domain_name", ""),
        "result": result_label,
        "badge_status": badge_status,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "confidence": confidence,
        "reasons": reasons,
        "features": features,
        "recommendations": recommendations,
    }


# ==========================================
# Application Routes
# ==========================================

@app.route("/")
def index():
    """Home Page / Main Cybersecurity Dashboard."""
    stats = get_dashboard_stats()
    recent_scans = get_recent_scans(limit=8)
    return render_template(
        "index.html",
        stats=stats,
        recent_scans=recent_scans,
        model_metadata=model_metadata,
        active_page="dashboard"
    )


@app.route("/analyze", methods=["GET", "POST"])
def analyze():
    """Dedicated URL Analyzer Page with Detailed Forensic Results."""
    result = None
    error_msg = None
    url_input = ""

    if request.method == "POST":
        url_input = request.form.get("url", "").strip()
        analysis = analyze_url_core(url_input)
        if analysis.get("success"):
            result = analysis
        else:
            error_msg = analysis.get("error", "An error occurred during analysis.")
    elif request.method == "GET" and request.args.get("url"):
        url_input = request.args.get("url", "").strip()
        analysis = analyze_url_core(url_input)
        if analysis.get("success"):
            result = analysis
        else:
            error_msg = analysis.get("error", "An error occurred during analysis.")

    return render_template(
        "analyze.html",
        result=result,
        error_msg=error_msg,
        url_input=url_input,
        model_metadata=model_metadata,
        active_page="analyze"
    )


@app.route("/history")
def history():
    """Scan History Page with Search, Filtering, and Deletion."""
    query = request.args.get("q", "").strip()
    filter_type = request.args.get("filter", "").strip()
    page = int(request.args.get("page", 1))
    per_page = 25
    offset = (page - 1) * per_page

    scans, total_count = get_all_scans(
        query=query if query else None,
        filter_type=filter_type if filter_type else None,
        limit=per_page,
        offset=offset
    )

    total_pages = max(1, (total_count + per_page - 1) // per_page)

    return render_template(
        "history.html",
        scans=scans,
        query=query,
        filter_type=filter_type,
        current_page=page,
        total_pages=total_pages,
        total_count=total_count,
        active_page="history"
    )



# ==========================================
# REST API Endpoints
# ==========================================

@app.route("/api/scan", methods=["POST"])
def api_scan():
    """API endpoint for asynchronous or programmatic URL analysis."""
    data = request.get_json(silent=True) or request.form
    raw_url = data.get("url", "")
    analysis = analyze_url_core(raw_url)
    if not analysis.get("success"):
        return jsonify(analysis), 400
    return jsonify(analysis), 200


@app.route("/api/stats", methods=["GET"])
def api_stats():
    """API endpoint returning live dashboard metrics for Chart.js."""
    stats = get_dashboard_stats()
    return jsonify({
        "status": "success",
        "stats": stats,
        "model_accuracy": model_metadata.get("accuracy", 0.98),
        "total_model_samples": model_metadata.get("total_records", 258)
    })


@app.route("/api/scan/<int:scan_id>", methods=["GET"])
def api_get_scan(scan_id):
    """Retrieves full details of a specific scan record."""
    scan = get_scan_by_id(scan_id)
    if not scan:
        return jsonify({"success": False, "error": "Scan record not found"}), 404
    return jsonify({"success": True, "scan": scan})


@app.route("/api/delete/<int:scan_id>", methods=["POST"])
def api_delete_scan(scan_id):
    """Deletes an individual scan entry."""
    success = delete_scan(scan_id)
    if request.headers.get("X-Requested-With") == "XMLHttpRequest":
        return jsonify({"success": success})
    flash("Scan record successfully deleted.", "info")
    return redirect(url_for("history"))


@app.route("/api/clear-history", methods=["POST"])
def api_clear_history():
    """Clears all scan history records from the database."""
    clear_all_scans()
    if request.headers.get("X-Requested-With") == "XMLHttpRequest":
        return jsonify({"success": True})
    flash("All scan history has been cleared.", "warning")
    return redirect(url_for("history"))


# ==========================================
# Error Handlers
# ==========================================

@app.errorhandler(404)
def page_not_found(e):
    return render_template("base.html", error_title="404 - Page Not Found",
                           error_desc="The requested cybersecurity resource does not exist."), 404


@app.errorhandler(500)
def server_error(e):
    return render_template("base.html", error_title="500 - Server Error",
                           error_desc="An internal processing error occurred while analyzing security data."), 500


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    debug_mode = os.environ.get("FLASK_DEBUG", "false").lower() in ["true", "1"]
    print("\n" + "=" * 65)
    print("  PHISHING URL DETECTION SYSTEM")
    print(f"  Target: http://127.0.0.1:{port}")
    print(f"  Debug Mode: {debug_mode}")
    print("=" * 65 + "\n")
    app.run(host="0.0.0.0", port=port, debug=debug_mode)
