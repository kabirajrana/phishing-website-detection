import streamlit as st
import joblib
import numpy as np
from urllib.parse import urlparse
import re

# === Load trained model ===
model = joblib.load("model1.pkl")

# === Feature extractor from pasted URL ===
def extract_features(url):
    try:
        parsed = urlparse(url)

        url_length = float(len(url))
        has_ip_address = int(bool(re.search(r'\d{1,3}(\.\d{1,3}){3}', url)))
        https = int(parsed.scheme == 'https')
        domain_age = float(2.0)  # Placeholder (can be updated)
        has_at_symbol = int("@" in url)
        redirects = int(url.count("//") > 2)
        prefix_suffix = int('-' in parsed.netloc)
        sfh = float(1.0 if any(kw in url.lower() for kw in ["login", "secure", "verify", "update"]) else 0.0)
        subdomains_count = int(len(parsed.netloc.split(".")) - 2 if len(parsed.netloc.split(".")) > 2 else 0)
        popup_window = int(0)  # Can't extract from URL alone

        return [
            url_length, has_ip_address, https, domain_age,
            has_at_symbol, redirects, prefix_suffix, sfh,
            subdomains_count, popup_window
        ]
    except Exception as e:
        st.error(f"Feature extraction failed: {e}")
        return None

# === Page Setup ===
st.set_page_config(page_title="Phishing URL Detector", layout="centered", page_icon="🛡️")
st.title("🛡️ Phishing Website Detector")
st.markdown("Check if a website is **legitimate** or **phishing** using one of the input methods below.")

# === Mode Selector ===
mode = st.radio("Select input method:", ["🔗 Paste URL", "🧪 Manual Input"])

# === Paste URL Mode ===
if mode == "🔗 Paste URL":
    url = st.text_input(
        "🌐 Enter a website URL to check:",
        placeholder="e.g. http://secure-login-update-paypal.com/verify"
    )

    if st.button("🔍 Predict from URL"):
        if url:
            features = extract_features(url)

            if features and len(features) == 10:
                try:
                    features_array = np.array(features).reshape(1, -1)
                    prediction = model.predict(features_array)[0]

                    label = "🛑 Phishing" if prediction == 1 else "✅ Legitimate"
                    bg = "#ffcccc" if prediction == 1 else "#e6ffe6"
                    text = "#b30000" if prediction == 1 else "#006600"

                    st.markdown(f"""
                        <div style="background-color:{bg};padding:20px;border-radius:10px;text-align:center;">
                            <h2 style="color:{text};">🔎 Prediction: {label}</h2>
                            <p style="color:gray;">Based on the pasted URL.</p>
                        </div>
                    """, unsafe_allow_html=True)
                except Exception as e:
                    st.error(f"Prediction error: {e}")
            else:
                st.error("🚨 Could not extract all required features from the URL.")
        else:
            st.warning("⚠️ Please paste a URL to test.")

# === Manual Input Mode ===
else:
    st.subheader("🧪 Manually Enter Feature Values")

    with st.form("manual_input_form"):
        col1, col2 = st.columns(2)

        with col1:
            url_length = st.number_input("🔗 URL Length", value=100.0)
            has_ip_address = st.selectbox("🌐 Has IP Address?", [0, 1])
            https = st.selectbox("🔒 HTTPS Present?", [0, 1])
            domain_age = st.number_input("📅 Domain Age (Years)", value=2.0)
            has_at_symbol = st.selectbox("📧 Contains @ Symbol?", [0, 1])

        with col2:
            redirects = st.number_input("🔁 Redirects", value=1)
            prefix_suffix = st.selectbox("💠 Prefix/Suffix (-)?", [0, 1])
            sfh = st.selectbox("🕵️ SFH Suspicious?", [0.0, 1.0])
            subdomains_count = st.number_input("📍 Subdomain Count", value=2)
            popup_window = st.selectbox("📤 Popup Window?", [0, 1])

        submit_manual = st.form_submit_button("🔍 Predict")

    if submit_manual:
        try:
            features = [
                float(url_length), int(has_ip_address), int(https), float(domain_age),
                int(has_at_symbol), int(redirects), int(prefix_suffix),
                float(sfh), int(subdomains_count), int(popup_window)
            ]
            features_array = np.array(features).reshape(1, -1)
            prediction = model.predict(features_array)[0]

            label = "🛑 Phishing" if prediction == 1 else "✅ Legitimate"
            bg = "#ffcccc" if prediction == 1 else "#e6ffe6"
            text = "#b30000" if prediction == 1 else "#006600"

            st.markdown(f"""
                <div style="background-color:{bg};padding:20px;border-radius:10px;text-align:center;">
                    <h2 style="color:{text};">🔎 Prediction: {label}</h2>
                    <p style="color:gray;">Based on your manual input.</p>
                </div>
            """, unsafe_allow_html=True)

        except Exception as e:
            st.error(f"Prediction error: {e}")

# === Footer ===
st.markdown("""
    <hr>
    <p style='text-align:center; font-size:12px; color:gray;'>
        🔬 Created by Kabiraj Rana • Powered by XGBoost + Streamlit
    </p>
""", unsafe_allow_html=True)
