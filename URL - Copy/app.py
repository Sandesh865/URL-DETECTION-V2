import os
from flask import Flask, request, render_template
import numpy as np
import onnxruntime as ort
import logging

# Set up logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

app = Flask(__name__)

# Model path
MODEL_PATH = "model/model.onnx"

# Load the model with error handling
try:
    if not os.path.exists(MODEL_PATH):
        raise FileNotFoundError(f"Model file not found at {MODEL_PATH}. Please download it.")
    session = ort.InferenceSession(MODEL_PATH, providers=["CPUExecutionProvider"])
    logger.info("Model loaded successfully.")
except Exception as e:
    logger.error(f"Failed to load model: {str(e)}")
    raise  # Stop execution if model fails to load

# Test the model with a sample input
def test_model():
    try:
        test_url = "https://example.com"
        inputs = np.array([test_url], dtype="str")
        results = session.run(None, {"inputs": inputs})[1]
        logger.info(f"Test prediction successful: {results}")
    except Exception as e:
        logger.error(f"Model test failed: {str(e)}")
        raise

test_model()  # Run a test on startup

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

        # Prepare input for the model
        inputs = np.array([url], dtype="str")
        logger.debug(f"Input URL: {url}")

        # Run inference
        results = session.run(None, {"inputs": inputs})[1]
        phishing_prob = results[0][1] * 100  # Phishing probability in %

        # Interpret result
        if phishing_prob > 50:
            result = f"Phishing URL detected! ({phishing_prob:.2f}% likelihood)"
            logger.info(f"Prediction: Phishing - {phishing_prob:.2f}%")
        else:
            result = f"URL seems safe. ({phishing_prob:.2f}% likelihood of phishing)"
            logger.info(f"Prediction: Safe - {phishing_prob:.2f}%")

        return render_template('index.html', prediction=result, url=url)

    except Exception as e:
        logger.error(f"Prediction error: {str(e)}")
        return render_template('index.html', error=f"An error occurred: {str(e)}", url=url)

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)