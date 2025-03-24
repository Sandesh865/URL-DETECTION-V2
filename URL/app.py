import os
from flask import Flask, request, render_template
import numpy as np
import onnxruntime as ort
import requests
import logging
import time
from datetime import datetime, timedelta
from urllib.parse import urlparse, urlunparse
import pickle
import os.path

# Set up logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

app = Flask(__name__)

# Load the ONNX model
MODEL_PATH = "model/model.onnx"
try:
    if not os.path.exists(MODEL_PATH):
        raise FileNotFoundError(f"Model file not found at {MODEL_PATH}.")
    session = ort.InferenceSession(MODEL_PATH, providers=["CPUExecutionProvider"])
    logger.info("Model loaded successfully.")
except Exception as e:
    logger.error(f"Failed to load model: {str(e)}")
    raise

# Cloudflare URL Scanner API settings
CLOUDFLARE_ACCOUNT_ID = "ad787388d0f70f036f58b3b799ec653a"
CLOUDFLARE_API_TOKEN = "_0jaMRE0qmjZb612weF8H69MYS3UTKP6WdM8o5Px"  # Replace with your new token if needed
CLOUDFLARE_SUBMIT_URL = f"https://api.cloudflare.com/client/v4/accounts/{CLOUDFLARE_ACCOUNT_ID}/urlscanner/v2/scan"
CLOUDFLARE_RESULT_URL = f"https://api.cloudflare.com/client/v4/accounts/{CLOUDFLARE_ACCOUNT_ID}/urlscanner/v2/result"
CLOUDFLARE_SCANS_URL = f"https://api.cloudflare.com/client/v4/accounts/{CLOUDFLARE_ACCOUNT_ID}/urlscanner/v2/scans"

# Google Safe Browsing API settings
GSB_API_KEY = "AIzaSyDd8fs_CmE7xXxnfrUOs2ddsOnW0jzYpnA"  # Replace with your actual API key
GSB_API_URL = "https://safebrowsing.googleapis.com/v4/threatMatches:find"

# Cache file for storing recent Cloudflare scan results
CACHE_FILE = "cloudflare_scan_cache.pkl"
SCAN_CACHE = {}
CACHE_DURATION = timedelta(hours=1)  # Cache scans for 1 hour

# Load cache from file
def load_cache():
    global SCAN_CACHE
    if os.path.exists(CACHE_FILE):
        try:
            with open(CACHE_FILE, "rb") as f:
                SCAN_CACHE = pickle.load(f)
            logger.debug("Loaded scan cache from file.")
        except Exception as e:
            logger.error(f"Failed to load scan cache: {str(e)}")
            SCAN_CACHE = {}

# Save cache to file
def save_cache():
    try:
        with open(CACHE_FILE, "wb") as f:
            pickle.dump(SCAN_CACHE, f)
        logger.debug("Saved scan cache to file.")
    except Exception as e:
        logger.error(f"Failed to save scan cache: {str(e)}")

# Load cache on startup
load_cache()

# Test the ONNX model
def test_model():
    try:
        test_url = "https://example.com"
        inputs = np.array([test_url], dtype="str")
        session.run(None, {"inputs": inputs})[1]
        logger.info("Model test successful.")
    except Exception as e:
        logger.error(f"Model test failed: {str(e)}")
        raise

test_model()

# Function to validate and normalize URL
def validate_url(url):
    try:
        # Parse the URL
        parsed = urlparse(url)
        # If no scheme, default to https
        if not parsed.scheme:
            url = "https://" + url
            parsed = urlparse(url)
        # Ensure the URL has a scheme and netloc
        if not parsed.scheme or not parsed.netloc:
            raise ValueError("Invalid URL: Missing scheme or domain.")
        # Reconstruct the URL
        return urlunparse(parsed)
    except Exception as e:
        logger.error(f"URL validation failed: {str(e)}")
        raise ValueError(f"Invalid URL: {str(e)}")

# Function to check for existing Cloudflare scans
def check_existing_cloudflare_scan(url):
    try:
        headers = {
            "Authorization": f"Bearer {CLOUDFLARE_API_TOKEN}",
            "Content-Type": "application/json"
        }
        # Query recent scans (last 24 hours)
        params = {
            "url": url,
            "limit": 1,
            "sort": "created_at:desc"  # Get the most recent scan
        }
        logger.debug(f"Checking for existing Cloudflare scan for URL: {url}")
        response = requests.get(CLOUDFLARE_SCANS_URL, headers=headers, params=params, timeout=10)
        response.raise_for_status()
        scans = response.json().get("scans", [])
        logger.debug(f"Existing scans response: {scans}")

        if scans:
            scan = scans[0]
            scan_id = scan["uuid"]
            created_at = datetime.fromisoformat(scan["created_at"].replace("Z", "+00:00"))
            # Check if the scan is recent (within the last 1 hour)
            if datetime.utcnow() - created_at.replace(tzinfo=None) < timedelta(hours=1):
                logger.debug(f"Found recent scan for {url}, scan ID: {scan_id}")
                return scan_id
        return None
    except requests.exceptions.RequestException as e:
        logger.error(f"Failed to check existing Cloudflare scans: {str(e)}")
        return None

# Function to verify URL with Cloudflare URL Scanner
def verify_with_cloudflare(url):
    try:
        # Validate and normalize the URL
        url = validate_url(url)
        logger.debug(f"Validated URL: {url}")

        # Check cache first
        if url in SCAN_CACHE:
            cached_result = SCAN_CACHE[url]
            cached_time = cached_result["timestamp"]
            if datetime.utcnow() - cached_time < CACHE_DURATION:
                logger.debug(f"Using cached Cloudflare result for {url}")
                return cached_result["result"]
            else:
                del SCAN_CACHE[url]  # Remove expired cache entry
                save_cache()

        # Check for existing scan
        scan_id = check_existing_cloudflare_scan(url)
        headers = {
            "Authorization": f"Bearer {CLOUDFLARE_API_TOKEN}",
            "Content-Type": "application/json"
        }

        if not scan_id:
            # Step 1: Submit the URL for scanning
            payload = {
                "url": url,
                "visibility": "public"
            }
            logger.debug(f"Submitting URL to Cloudflare with payload: {payload}")
            submit_response = requests.post(
                CLOUDFLARE_SUBMIT_URL,
                headers=headers,
                json=payload,
                timeout=10
            )
            submit_response.raise_for_status()
            logger.debug(f"Cloudflare submit response: {submit_response.text}")
            scan_id = submit_response.json()["uuid"]

        # Step 2: Poll for the scan result (30 seconds total)
        result_url = f"{CLOUDFLARE_RESULT_URL}/{scan_id}"
        for attempt in range(10):  # Poll up to 10 times, ~30s total
            logger.debug(f"Polling Cloudflare result (attempt {attempt + 1})...")
            result_response = requests.get(result_url, headers=headers, timeout=10)
            if result_response.status_code == 200:
                result_data = result_response.json()
                logger.debug(f"Cloudflare full result response: {result_data}")
                scan_state = result_data.get("state", "unknown")
                logger.debug(f"Scan state: {scan_state}")
                if scan_state == "completed":
                    verdicts = result_data.get("verdicts", {}).get("overall", {})
                    page = result_data.get("page", {})
                    technologies = result_data.get("meta", {}).get("processors", {}).get("wappa", {}).get("data", {}).get("technologies", [])
                    result = {
                        "malicious": verdicts.get("malicious", False),
                        "score": verdicts.get("score", 0),
                        "categories": verdicts.get("categories", []),
                        "ip": page.get("ip", "Unknown"),
                        "country": page.get("country", "Unknown"),
                        "technologies": [tech.get("name", "Unknown") for tech in technologies] if technologies else [],
                        "status": "completed",
                        "source": "Cloudflare"
                    }
                    # Cache the result
                    SCAN_CACHE[url] = {
                        "timestamp": datetime.utcnow(),
                        "result": result
                    }
                    save_cache()
                    return result
                elif scan_state in ["failed", "error"]:
                    return {"error": "Cloudflare scan failed. The website may be blocking the scan.", "status": "failed"}
                time.sleep(3)  # Wait 3 seconds before polling again
            elif result_response.status_code == 429:
                return {"error": "Cloudflare rate limit exceeded. Please try again later.", "status": "failed"}
        return {"error": "Cloudflare scan timed out after 30 seconds. The website may be blocking the scan or the scan queue is delayed.", "status": "timeout"}
    except requests.exceptions.HTTPError as e:
        if e.response.status_code == 400:
            logger.error(f"Cloudflare 400 Bad Request: {e.response.text}")
            return {"error": f"Cloudflare scan failed: Invalid request. Please ensure the URL is valid and try again.", "status": "failed"}
        elif e.response.status_code == 403:
            logger.error("Cloudflare 403 Forbidden: Check API token permissions.")
            return {"error": "Cloudflare scan failed: API token lacks necessary permissions.", "status": "failed"}
        elif e.response.status_code == 409:
            logger.error("Cloudflare 409 Conflict: A scan for this URL is already in progress or recently completed.")
            # Try to find the existing scan
            scan_id = check_existing_cloudflare_scan(url)
            if scan_id:
                # Poll for the existing scan (30 seconds total)
                result_url = f"{CLOUDFLARE_RESULT_URL}/{scan_id}"
                for attempt in range(10):
                    logger.debug(f"Polling existing Cloudflare result (attempt {attempt + 1})...")
                    result_response = requests.get(result_url, headers=headers, timeout=10)
                    if result_response.status_code == 200:
                        result_data = result_response.json()
                        logger.debug(f"Cloudflare full result response: {result_data}")
                        scan_state = result_data.get("state", "unknown")
                        if scan_state == "completed":
                            verdicts = result_data.get("verdicts", {}).get("overall", {})
                            page = result_data.get("page", {})
                            technologies = result_data.get("meta", {}).get("processors", {}).get("wappa", {}).get("data", {}).get("technologies", [])
                            result = {
                                "malicious": verdicts.get("malicious", False),
                                "score": verdicts.get("score", 0),
                                "categories": verdicts.get("categories", []),
                                "ip": page.get("ip", "Unknown"),
                                "country": page.get("country", "Unknown"),
                                "technologies": [tech.get("name", "Unknown") for tech in technologies] if technologies else [],
                                "status": "completed",
                                "source": "Cloudflare"
                            }
                            # Cache the result
                            SCAN_CACHE[url] = {
                                "timestamp": datetime.utcnow(),
                                "result": result
                            }
                            save_cache()
                            return result
                        elif scan_state in ["failed", "error"]:
                            return {"error": "Cloudflare scan failed. The website may be blocking the scan.", "status": "failed"}
                    time.sleep(3)
                return {"error": "Cloudflare scan timed out after 30 seconds. The website may be blocking the scan or the scan queue is delayed.", "status": "timeout"}
            return {"error": "Cloudflare scan conflict: A scan for this URL is already in progress or recently completed, but could not retrieve results.", "status": "failed"}
        elif e.response.status_code == 429:
            logger.error("Cloudflare rate limit exceeded.")
            return {"error": "Cloudflare rate limit exceeded. Please try again later.", "status": "failed"}
        logger.error(f"Cloudflare API request failed: {str(e)}")
        return {"error": f"Cloudflare scan failed: {str(e)}", "status": "failed"}
    except Exception as e:
        logger.error(f"Unexpected error in Cloudflare verification: {str(e)}")
        return {"error": str(e), "status": "failed"}

# Fallback function to verify URL with Google Safe Browsing
def verify_with_google_safe_browsing(url):
    try:
        # Validate and normalize the URL
        url = validate_url(url)
        logger.debug(f"Validated URL for Google Safe Browsing: {url}")

        # Check if API key is set
        if GSB_API_KEY == "your_google_safe_browsing_api_key_here":
            return {"error": "Google Safe Browsing API key not configured. Please contact the administrator.", "status": "failed"}

        # Prepare the request payload
        payload = {
            "client": {
                "clientId": "yourcompanyname",
                "clientVersion": "1.0"
            },
            "threatInfo": {
                "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url}]
            }
        }
        params = {"key": GSB_API_KEY}
        logger.debug(f"Submitting URL to Google Safe Browsing: {url}")
        response = requests.post(
            GSB_API_URL,
            params=params,
            json=payload,
            timeout=10
        )
        response.raise_for_status()
        logger.debug(f"Google Safe Browsing response: {response.text}")
        data = response.json()

        if "matches" in data:
            threats = [match["threatType"] for match in data["matches"]]
            return {
                "malicious": True,
                "threats": threats,
                "status": "completed",
                "source": "Google Safe Browsing"
            }
        return {
            "malicious": False,
            "threats": [],
            "status": "completed",
            "source": "Google Safe Browsing"
        }
    except requests.exceptions.RequestException as e:
        logger.error(f"Google Safe Browsing API request failed: {str(e)}")
        return {"error": f"Google Safe Browsing scan failed: {str(e)}", "status": "failed"}
    except Exception as e:
        logger.error(f"Unexpected error in Google Safe Browsing verification: {str(e)}")
        return {"error": str(e), "status": "failed"}

# Home route
@app.route('/')
def home():
    return render_template('index.html')

# Prediction route
@app.route('/predict', methods=['POST'])
def predict():
    try:
        url = request.form.get('url', '').strip()
        if not url:
            return render_template('index.html', error="Please enter a URL.")

        # ONNX model prediction
        inputs = np.array([url], dtype="str")
        results = session.run(None, {"inputs": inputs})[1]
        phishing_prob = results[0][1] * 100
        is_phishing = phishing_prob > 50
        model_result = f"Phishing URL detected! ({phishing_prob:.2f}% likelihood)" if is_phishing else f"URL seems safe. ({phishing_prob:.2f}% likelihood)"

        # Verify with Cloudflare URL Scanner
        scan_result = verify_with_cloudflare(url)
        logger.debug(f"Cloudflare result: {scan_result}")

        # Fallback to Google Safe Browsing if Cloudflare fails
        if scan_result.get("status") in ["failed", "timeout"]:
            logger.debug("Cloudflare scan failed, falling back to Google Safe Browsing...")
            cloudflare_error = scan_result.pop("error", None)  # Preserve Cloudflare error message
            scan_result = verify_with_google_safe_browsing(url)
            scan_result["cloudflare_error"] = cloudflare_error

        # If both APIs fail, provide a default result
        if scan_result.get("status") in ["failed", "timeout"]:
            scan_result = {
                "malicious": None,
                "status": "failed",
                "source": "None",
                "error": "Both Cloudflare and Google Safe Browsing scans failed. Please try again later.",
                "cloudflare_error": scan_result.get("cloudflare_error"),
                "google_error": scan_result.get("error")
            }

        return render_template(
            'index.html',
            url=url,
            model_prediction=model_result,
            is_phishing=is_phishing,
            scan_malicious=scan_result.get("malicious"),
            scan_score=scan_result.get("score"),
            scan_categories=scan_result.get("categories"),
            scan_ip=scan_result.get("ip"),
            scan_country=scan_result.get("country"),
            scan_technologies=scan_result.get("technologies"),
            scan_threats=scan_result.get("threats"),
            scan_error=scan_result.get("error"),
            scan_status=scan_result.get("status"),
            scan_source=scan_result.get("source"),
            cloudflare_error=scan_result.get("cloudflare_error"),
            google_error=scan_result.get("google_error")
        )

    except Exception as e:
        logger.error(f"Prediction error: {str(e)}")
        return render_template('index.html', error=f"An error occurred: {str(e)}", url=url)

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)