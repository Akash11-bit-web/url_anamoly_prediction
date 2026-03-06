import streamlit as st
import requests

API_PREDICT = "https://url-anamoly-prediction.onrender.com/predict"
API_INFO    = "https://url-anamoly-prediction.onrender.com/domain-info"

st.set_page_config(page_title="URL Anomaly Detector", page_icon="🔍", layout="centered")

st.title("🔍 URL Anomaly Detection System")
st.markdown("Enter any URL to check if it's **safe or malicious** with detailed insights.")

url_input = st.text_input("🌐 Enter URL", placeholder="https://example.com")

if st.button("🔎 Analyze URL"):
    if not url_input.strip():
        st.warning("⚠️ Please enter a URL.")
    else:
        with st.spinner("Analyzing URL..."):
            try:
                pred_resp = requests.post(API_PREDICT, json={"url": url_input})
                pred_data = pred_resp.json()

                st.markdown("---")

                # ══════════════════════════════════════════
                # ✅ LEGITIMATE URL — Show Domain InfoBox
                # ══════════════════════════════════════════
                if pred_data["prediction"] == 1:
                    st.success(f"### ✅ This URL is LEGITIMATE")
                    st.write(f"**Confidence:** {pred_data['confidence']}")

                    st.markdown("---")
                    st.subheader("🌐 Domain Intelligence Report")

                    with st.spinner("Fetching domain details..."):
                        info_resp = requests.post(API_INFO, json={"url": url_input})
                        info = info_resp.json()

                    if "error" not in info:
                        col1, col2 = st.columns(2)

                        with col1:
                            st.markdown("#### 📋 Registration Info")
                            st.info(f"🌍 **Domain:** {info.get('domain', 'N/A')}")
                            st.info(f"🏢 **Organization:** {info.get('organization', 'N/A')}")
                            st.info(f"📍 **Country:** {info.get('country', 'N/A')}")
                            st.info(f"🏦 **Registrar:** {info.get('registrar', 'N/A')}")
                            st.info(f"📅 **Created On:** {info.get('creation_date', 'N/A')}")
                            st.info(f"📅 **Domain Age:** {info.get('domain_age', 'N/A')}")
                            st.info(f"⏳ **Expires On:** {info.get('expiry_date', 'N/A')}")

                        with col2:
                            st.markdown("#### 🔧 Technical Info")
                            st.info(f"📡 **IP Address:** {info.get('ip_address', 'N/A')}")
                            st.info(f"🔒 **SSL Status:** {info.get('ssl_valid', 'N/A')}")
                            st.info(f"📅 **SSL Expiry:** {info.get('ssl_expiry', 'N/A')}")
                            st.info(f"⚡ **Server:** {info.get('server', 'N/A')}")
                            st.info(f"📊 **Status Code:** {info.get('status_code', 'N/A')}")
                            st.info(f"🔁 **Redirects:** {'Yes' if info.get('redirects') else 'No'}")
                            st.info(f"🔗 **Final URL:** {info.get('final_url', 'N/A')}")

                        st.markdown("#### 🖥️ Name Servers")
                        for ns in info.get("name_servers", []):
                            st.code(ns)
                    else:
                        st.warning("Could not retrieve domain details.")

                # ══════════════════════════════════════════
                # 🚨 PHISHING URL — Show Why + Attack Type
                # ══════════════════════════════════════════
                else:
                    st.error(f"### 🚨 This URL is MALICIOUS / PHISHING")
                    st.write(f"**Confidence:** {pred_data['confidence']}")

                    st.markdown("---")

                    # Risk Level
                    st.markdown(f"### Risk Level: {pred_data.get('risk_level', '🔴 High Risk')}")

                    # Attack Types
                    st.markdown("---")
                    st.subheader("⚠️ Type of Attack Detected")
                    for attack in pred_data.get("attack_types", []):
                        st.error(f"🎯 {attack}")

                    # Why it's suspicious
                    st.markdown("---")
                    st.subheader("🔍 Why This URL is Suspicious")
                    reasons = pred_data.get("reasons", [])
                    if reasons:
                        for reason in reasons:
                            st.warning(reason)
                    else:
                        st.warning("🔴 URL pattern matches known phishing structures")

                    # Safety Tips
                    st.markdown("---")
                    st.subheader("🛡️ What You Should Do")
                    st.markdown("""
                    - ❌ **Do NOT click** or visit this URL
                    - ❌ **Do NOT enter** any personal information
                    - ❌ **Do NOT download** anything from this link
                    - ✅ **Report** this URL to your IT/security team
                    - ✅ **Use** [VirusTotal](https://www.virustotal.com) for further verification
                    """)

            except Exception as e:
                st.error(f"❌ Could not connect to backend: {e}")
