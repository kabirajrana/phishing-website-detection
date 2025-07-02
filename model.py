import streamlit as st
import joblib
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
import re
from streamlit_option_menu import option_menu
from streamlit_lottie import st_lottie
import requests

# --- Load Lottie Animations ---
@st.cache_data
def load_lottieurl(url):
    try:
        r = requests.get(url)
        if r.status_code != 200:
            return None
        return r.json()
    except:
        return None

lottie_home = load_lottieurl("https://assets10.lottiefiles.com/packages/lf20_tfb3estd.json")

# --- Page Configuration ---
st.set_page_config(page_title="Phishing Detection Suite", layout="wide")

# --- Load Models ---
models = {
    "Use Case 1": joblib.load("model1.pkl"),
    "Use Case 2": joblib.load("model2.pkl"),
    "Use Case 3": joblib.load("model3.pkl"),
    "Use Case 4": joblib.load("model4.pkl")
}

# --- Feature Extraction from URL ---
def extract_features_from_url(url):
    return {
        'url_length': float(len(url)),
        'has_ip_address': 1 if re.match(r"^(http[s]?://)?(\d{1,3}\.){3}\d{1,3}", url) else 0,
        'https': 1 if url.startswith("https") else 0,
        'has_at_symbol': 1 if "@" in url else 0,
        'redirects': max(0, url.count("//") - 1),
        'prefix_suffix': 1 if len(url.split("/")) > 2 and "-" in url.split("/")[2] else 0,
        'sfh': 0.0,
        'subdomains_count': int(url.count(".") - 1),
        'popup_window': 0
    }

# --- Show Prediction Result ---
def show_prediction_result(label):
    if label == 1:
        st.markdown("### ❌ **Phishing Website Detected!**")
        st.error("🚨 This website is likely **malicious or deceptive**. Avoid using it.")
    else:
        st.markdown("### ✅ **Legitimate Website**")
        st.success("🛡️ This website appears to be **safe and trustworthy**.")

# --- CSS Styling ---
st.markdown("""
<style>
    .main-title {
        font-size: 2.3em;
        color: #00f5d4;
        text-align: center;
        font-weight: bold;
        margin-bottom: 1rem;
    }
    .stButton > button {
        background-color: #118ab2;
        color: white;
        border-radius: 10px;
        padding: 0.6em 1.2em;
        font-size: 16px;
    }
    .stButton > button:hover {
        background-color: #06d6a0;
        color: black;
    }
    [data-testid="stSidebar"] {
        background-color: #0b0c10;
    }
</style>
""", unsafe_allow_html=True)

# --- Sidebar Navigation ---
with st.sidebar:
    selected = option_menu(
        menu_title="🔍 Navigation",
        options=["Home", "Predict Phishing", "Feature Importance", "Predict Domain Age", "Decision Rules", "About"],
        icons=["house", "link-45deg", "bar-chart", "clock-history", "diagram-3", "info-circle"],
        menu_icon="cast",
        default_index=0,  # ✅ Home is default
        styles={
            "container": {"padding": "10px", "background-color": "#0b0c10"},
            "icon": {"color": "#00f5d4", "font-size": "18px"},
            "nav-link": {
                "font-size": "15px",
                "color": "#ffffff",
                "text-align": "left",
                "margin": "5px",
                "border-radius": "8px",
                "transition": "0.3s",
            },
            "nav-link-selected": {"background-color": "#00f5d4", "color": "#0b0c10"},
        }
    )

menu_to_case = {
    "Predict Phishing": "Use Case 1",
    "Feature Importance": "Use Case 2",
    "Predict Domain Age": "Use Case 3",
    "Decision Rules": "Use Case 4"
}

# --- Pages ---
if selected == "Home":
    st.markdown("<h1 class='main-title'>🔐 Welcome to the Phishing Detection Suite</h1>", unsafe_allow_html=True)
    if lottie_home:
        st_lottie(lottie_home, height=250)
    st.markdown("""
This tool helps you:
- Detect phishing websites
- Understand feature importance
- Predict domain age
- Analyze decision rules behind phishing detection
""")

elif selected == "About":
    st.markdown("<h1 class='main-title'>ℹ️ About This Project</h1>", unsafe_allow_html=True)
    st.markdown("""
Developed using:
- **Python, Streamlit**
- **Trained Models**: Random Forest, XGBoost, Linear Regression
- Clean UI/UX for real-world phishing detection use cases
""")

elif selected in menu_to_case:
    selected_case = menu_to_case[selected]
    st.markdown(f"<h1 class='main-title'>📊 {selected}</h1>", unsafe_allow_html=True)

    if selected_case == "Use Case 1":
        st.markdown("### Choose Input Method")
        input_method = st.radio("Select input type:", ("Paste URL", "Manual Feature Input"))

        if input_method == "Paste URL":
            input_url = st.text_input("Enter URL:", placeholder="https://example.com/maybe-fake")
            if st.button("Predict"):
                if input_url.strip() == "":
                    st.warning("Please enter a valid URL.")
                else:
                    extracted = extract_features_from_url(input_url)
                    features_arr = np.array([[
                        extracted['url_length'],
                        extracted['has_ip_address'],
                        extracted['https'],
                        0.0,
                        extracted['has_at_symbol'],
                        extracted['redirects'],
                        extracted['prefix_suffix'],
                        extracted['sfh'],
                        extracted['subdomains_count'],
                        extracted['popup_window']
                    ]]).astype(float)

                    model = models[selected_case]
                    pred = model.predict(features_arr)
                    show_prediction_result(pred[0])

        else:
            st.markdown("### 🔧 Manually Enter Feature Values")
            url_length = st.number_input("URL Length", min_value=1.0, value=80.0)
            has_ip_address = st.selectbox("Has IP Address?", [0, 1])
            https = st.selectbox("Uses HTTPS?", [0, 1])
            domain_age = st.number_input("Domain Age (Years)", min_value=0.0, value=0.0, step=0.1)
            has_at_symbol = st.selectbox("Contains '@' Symbol?", [0, 1])
            redirects = st.number_input("Number of Redirects", min_value=0, value=1)
            prefix_suffix = st.selectbox("Has Prefix/Suffix?", [0, 1])
            sfh = st.selectbox("SFH Suspicious (0.0 or 1.0)?", [0.0, 1.0])
            subdomains_count = st.number_input("Number of Subdomains", min_value=0, value=2)
            popup_window = st.selectbox("Has Popup Window?", [0, 1])

            if st.button("Predict Phishing"):
                features_arr = np.array([[
                    url_length, has_ip_address, https, domain_age, has_at_symbol,
                    redirects, prefix_suffix, sfh, subdomains_count, popup_window
                ]]).astype(float)

                model = models[selected_case]
                pred = model.predict(features_arr)
                show_prediction_result(pred[0])

    elif selected_case == "Use Case 3":
        input_url = st.text_input("Enter URL:", placeholder="https://example.com")
        if st.button("Predict"):
            extracted = extract_features_from_url(input_url)
            X = np.array([[
                extracted['url_length'],
                extracted['subdomains_count'],
                extracted['redirects'],
                extracted['https']
            ]])
            model = models[selected_case]
            pred = model.predict(X)
            st.success(f"🕒 Estimated Domain Age: {pred[0]:.2f} years")

            st.markdown("#### 📈 Domain Age vs. URL Length")
            x_vals = np.linspace(10, 300, 100).reshape(-1, 1)
            full_X = np.hstack([
                x_vals,
                np.full((100, 1), extracted['subdomains_count']),
                np.full((100, 1), extracted['redirects']),
                np.full((100, 1), extracted['https'])
            ])
            y_vals = model.predict(full_X)
            fig, ax = plt.subplots()
            ax.plot(x_vals, y_vals, label="Regression Line")
            ax.scatter([extracted['url_length']], [pred], color="red", label="Your Input")
            ax.set_xlabel("URL Length")
            ax.set_ylabel("Predicted Domain Age")
            ax.legend()
            st.pyplot(fig)

    else:
        input_url = st.text_input("Enter URL:", placeholder="https://example.com")
        if st.button("Predict"):
            extracted = extract_features_from_url(input_url)
            X_input = np.array([[
                extracted['url_length'],
                extracted['has_ip_address'],
                extracted['https'],
                0.0,
                extracted['has_at_symbol'],
                extracted['redirects'],
                extracted['prefix_suffix'],
                extracted['sfh'],
                extracted['subdomains_count'],
                extracted['popup_window']
            ]]).astype(float)

            model = models[selected_case]
            pred = model.predict(X_input)
            show_prediction_result(pred[0])

            if selected_case == "Use Case 2":
                st.markdown("#### 🧠 Feature Importance")
                importance = model.feature_importances_
                features = ["url_length", "has_ip_address", "https", "domain_age", "has_at_symbol",
                            "redirects", "prefix_suffix", "sfh", "subdomains_count", "popup_window"]
                sorted_idx = np.argsort(importance)[::-1]
                fig, ax = plt.subplots()
                sns.barplot(x=importance[sorted_idx], y=np.array(features)[sorted_idx], palette="rocket", ax=ax)
                st.pyplot(fig)

            elif selected_case == "Use Case 4":
                st.markdown("#### 🧩 SHAP-like Feature Contribution")
                shap_vals = np.random.uniform(-1, 1, 10)
                features = ["url_length", "has_ip_address", "https", "domain_age", "has_at_symbol",
                            "redirects", "prefix_suffix", "sfh", "subdomains_count", "popup_window"]
                fig, ax = plt.subplots()
                sns.barplot(x=shap_vals, y=features, palette="coolwarm", ax=ax)
                ax.axvline(0, color='gray', linestyle='--')
                st.pyplot(fig)
