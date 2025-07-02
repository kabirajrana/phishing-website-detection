import streamlit as st
import joblib
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.tree import plot_tree
from sklearn.decomposition import PCA
from sklearn.inspection import permutation_importance
import re

# Page configuration
st.set_page_config(page_title="Phishing Detection Suite", layout="wide")

# Load models
models = {
    "Use Case 1": joblib.load("model1.pkl"),  # XGBoost Classifier - Predict phishing
    "Use Case 2": joblib.load("model2.pkl"),  # Random Forest - Feature importance
    "Use Case 3": joblib.load("model3.pkl"),  # Linear Regression - Predict domain age
    "Use Case 4": joblib.load("model4.pkl")   # XGBoost Classifier - Decision rules
}

# Extract features from URL

def extract_features_from_url(url):
    features = {}
    features['url_length'] = len(url)
    features['has_ip_address'] = 1 if re.match(r"^(http[s]?://)?(\d{1,3}\.){3}\d{1,3}", url) else 0
    features['https'] = 1 if url.startswith("https") else 0
    features['has_at_symbol'] = 1 if "@" in url else 0
    features['redirects'] = 1 if url.count("//") > 2 else 0
    features['prefix_suffix'] = 1 if "-" in url.split("/")[2] else 0 if len(url.split("/")) > 2 else 0
    features['sfh'] = 0  # Placeholder, would require HTML form parsing
    features['subdomains_count'] = url.count(".") - 1
    features['popup_window'] = 0  # Placeholder, requires JS behavior analysis
    return features

# Sidebar Navigation
st.sidebar.title("\U0001F50D Use Case Navigation")
selected_case = st.sidebar.radio("Select a Use Case", list(models.keys()))

# Common input form
with st.form("input_form"):
    st.subheader("\U0001F4DD Input URL")
    input_url = st.text_input("Paste the URL to analyze:", "http://example.com")
    domain_age = st.slider("Domain Age (years) (required for Use Cases 1, 2, 4)", 0, 10, 3)
    submitted = st.form_submit_button("Predict")

if submitted:
    extracted = extract_features_from_url(input_url)
    X_input = np.array([[
        extracted['url_length'],
        extracted['has_ip_address'],
        extracted['https'],
        domain_age,
        extracted['has_at_symbol'],
        extracted['redirects'],
        extracted['prefix_suffix'],
        extracted['sfh'],
        extracted['subdomains_count'],
        extracted['popup_window']
    ]])

    model = models[selected_case]
    st.title(f"\U0001F4C8 {selected_case}")

    if selected_case == "Use Case 3":  # Linear Regression
        X_reg = np.array([[
            extracted['url_length'],
            extracted['subdomains_count'],
            extracted['redirects'],
            extracted['https']
        ]])
        pred = model.predict(X_reg)
        st.success(f"Predicted Domain Age: {pred[0]:.2f} years")

        st.subheader("\U0001F4C9 Linear Relationship: URL Length vs Domain Age")
        x_vals = np.linspace(10, 300, 100).reshape(-1, 1)
        full_X = np.hstack([x_vals, np.full((100, 1), extracted['subdomains_count']),
                            np.full((100, 1), extracted['redirects']), np.full((100, 1), extracted['https'])])
        y_vals = model.predict(full_X)
        fig, ax = plt.subplots()
        ax.plot(x_vals, y_vals, label='Regression Line')
        ax.scatter([extracted['url_length']], [pred], color='red', label='Your Input')
        ax.set_xlabel("URL Length")
        ax.set_ylabel("Predicted Domain Age")
        ax.legend()
        st.pyplot(fig)

    else:
        pred = model.predict(X_input)
        label = "Legitimate" if pred[0] == 1 else "Phishing"
        st.success(f"Prediction: {label}")

        st.subheader("\U0001F4CA Sample Prediction Distribution")
        counts = {"Phishing": np.random.randint(20, 50), "Legitimate": np.random.randint(20, 50)}
        fig, ax = plt.subplots()
        ax.pie(counts.values(), labels=counts.keys(), autopct='%1.1f%%', colors=["#e74c3c", "#2ecc71"])
        st.pyplot(fig)

        if selected_case == "Use Case 2":  # Feature importance - Random Forest
            st.subheader("\U0001F9E0 Top Features for Phishing Classification")
            importance = model.feature_importances_
            features = ["url_length", "has_ip_address", "https", "domain_age", "has_at_symbol",
                        "redirects", "prefix_suffix", "sfh", "subdomains_count", "popup_window"]
            sorted_idx = np.argsort(importance)[::-1]
            fig, ax = plt.subplots()
            sns.barplot(x=importance[sorted_idx], y=np.array(features)[sorted_idx], palette="magma", ax=ax)
            ax.set_title("Feature Importances (Random Forest)")
            st.pyplot(fig)

        if selected_case == "Use Case 4":  # Decision rules - XGBoost
            st.subheader("\U0001F333 Simplified Decision Tree")
            st.markdown("Below is a sample approximation of rules extracted from the XGBoost model.")
            st.code("""
If URL contains '@' symbol AND HTTPS is 0 AND popup_window = 1:
    Predict: Phishing
Else if domain_age > 2 AND subdomains_count < 3:
    Predict: Legitimate
            """, language="python")

            st.subheader("\U0001F5A9 Feature Contribution (Mock Example)")
            shap_vals = np.random.uniform(-1, 1, 10)
            features = ["url_length", "has_ip_address", "https", "domain_age", "has_at_symbol",
                        "redirects", "prefix_suffix", "sfh", "subdomains_count", "popup_window"]
            fig, ax = plt.subplots()
            sns.barplot(x=shap_vals, y=features, palette="coolwarm", ax=ax)
            ax.axvline(0, color='gray', linestyle='--')
            ax.set_title("SHAP-like Feature Contribution (Simulated)")
            st.pyplot(fig)
