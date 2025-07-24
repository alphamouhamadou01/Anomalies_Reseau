import streamlit as st
import pandas as pd
import requests
import plotly.express as px
import plotly.graph_objects as go
from io import BytesIO
from fpdf import FPDF
from mailjet_rest import Client
import json

# === CONFIGURATION DE LA PAGE ===
st.set_page_config(
    page_title="Détection des anomalies réseau avec l'IA No-Code",
    layout="wide"
)

# === TITRE PRINCIPAL ===
st.markdown("""
<h1 style="text-align:center; color:#003366;">
🔍 Détection des anomalies réseau avec l'IA No-Code
</h1>

""", unsafe_allow_html=True)

# === CONFIGURATION API DATAROBOT (À REMPLACER PAR TES VRAIES CLÉS) ===
API_KEY = "Njg4MjhjNmQ5NmM3NzJkMzkwZTAxNWY4OmNubkZpa0JTT1djREFIbUdiVU1zU2R1RG1qbDlmRGNGcEtpSWhOZHJ1ZVE9"
DATAROBOT_KEY = "302bde87-f947-4fa6-bc24-560a7b1c8fec"
DEPLOYMENT_ID = "68828929f79deaaf7f05ceee"
API_URL = f"https://app.datarobot.com/api/v2/deployments/68828929f79deaaf7f05ceee/predictions"


# === CONFIGURATION MAILJET (À REMPLACER PAR TES VRAIES CLÉS) ===
MAILJET_API_KEY = "7c60634f50636b9721a31596b414f9ca"
MAILJET_API_SECRET = "3c8681b84ff47bcadcb38762df164c33"
EMAIL_SENDER = "mouhamadoualpha.ba@uadb.edu.sn"
EMAIL_RECEIVER = "bamouhamadou938@gmail.com"

def envoyer_alerte_email_mailjet(prediction, score):
    try:
        mailjet = Client(auth=(MAILJET_API_KEY, MAILJET_API_SECRET), version='v3.1')
        data = {
            'Messages': [
                {
                    "From": {
                        "Email": EMAIL_SENDER,
                        "Name": "Détection Anomalies Réseau"
                    },
                    "To": [
                        {
                            "Email": EMAIL_RECEIVER,
                            "Name": "Administrateur Réseau"
                        }
                    ],
                    "Subject": f"🚨 Alerte Sécurité : {prediction.upper()} détecté !",
                    "TextPart": f"Une anomalie réseau a été détectée.\n"
                                f"Type d'attaque : {prediction}\n"
                                f"Niveau de dangerosité : {score}%\n\n"
                                f"Recommandation : Surveillez immédiatement votre réseau.",
                    "HTMLPart": f"<h3>🚨 Alerte de Sécurité</h3>"
                                f"<p><b>Type d'attaque :</b> {prediction}<br>"
                                f"<b>Niveau de dangerosité :</b> {score}%</p>"
                                f"<p><b>Action :</b> Surveillez immédiatement votre réseau.</p>"
                }
            ]
        }
        result = mailjet.send.create(data=data)
        if result.status_code == 200:
            st.info("📧 Alerte e-mail envoyée via Mailjet.")
        else:
            st.warning("⚠ L'envoi de l'alerte a échoué.")
    except Exception as e:
        st.warning(f"⚠ Erreur lors de l'envoi de l'alerte : {e}")

# === INITIALISATION HISTORIQUE ===
if "historique" not in st.session_state:
    st.session_state["historique"] = pd.DataFrame(columns=["Prediction", "Dangerosité", "Horodatage"])

# === TABLEAU DANGEROSITÉ ===
dangerosite = {
    "normal": 10,
    "icmp-echo": 30,
    "tcp-syn": 60,
    "udp-flood": 70,
    "httpFlood": 80,
    "slowloris": 75,
    "slowpost": 70,
    "bruteForce": 90
}

solutions = {
    "normal": "Aucune action requise.",
    "icmp-echo": "Limiter les requêtes ICMP via le pare-feu.",
    "tcp-syn": "Activer SYN Cookies et limiter les connexions simultanées.",
    "udp-flood": "Configurer des filtres anti-UDP flood et activer QoS.",
    "httpFlood": "Utiliser un WAF et limiter les requêtes HTTP.",
    "slowloris": "Utiliser un reverse proxy et limiter la durée des sessions.",
    "slowpost": "Configurer des délais plus courts pour les envois POST.",
    "bruteForce": "Bloquer les IP suspectes et renforcer l'authentification."
}

# === ONGLET INTERFACE ===
onglets = st.tabs(["🔎 Prédiction", "📊 Analyse Globale", "📜 Historique"])

# -------------------- ONGLET 1 : PRÉDICTION --------------------
with onglets[0]:
    st.subheader("Choisissez une méthode de prédiction")
    choix = st.radio("", ["Prédiction manuelle", "Prédiction via fichier CSV"])

    # ---- PRÉDICTION MANUELLE ----
    if choix == "Prédiction manuelle":
        with st.form("formulaire_manuel"):
            col1, col2, col3 = st.columns(3)
            with col1:
                ifInOctets11 = st.number_input("ifInOctets11", min_value=0)
                ifOutOctets11 = st.number_input("ifOutOctets11", min_value=0)
                ifoutDiscards11 = st.number_input("ifoutDiscards11", min_value=0)
                ifInUcastPkts11 = st.number_input("ifInUcastPkts11", min_value=0)
                ifInNUcastPkts11 = st.number_input("ifInNUcastPkts11", min_value=0)
                ifInDiscards11 = st.number_input("ifInDiscards11", min_value=0)
                ifOutUcastPkts11 = st.number_input("ifOutUcastPkts11", min_value=0)
                ifOutNUcastPkts11 = st.number_input("ifOutNUcastPkts11", min_value=0)
                tcpOutRsts = st.number_input("tcpOutRsts", min_value=0)
            with col2:
                tcpInSegs = st.number_input("tcpInSegs", min_value=0)
                tcpOutSegs = st.number_input("tcpOutSegs", min_value=0)
                tcpPassiveOpens = st.number_input("tcpPassiveOpens", min_value=0)
                tcpRetransSegs = st.number_input("tcpRetransSegs", min_value=0)
                tcpEstabResets = st.number_input("tcpEstabResets", min_value=0)
                tcpCurrEstab = st.number_input("tcpCurrEstab", min_value=0)
                tcp_question_active_opens = st.number_input("tcp?ActiveOpens", min_value=0)
                udpInDatagrams = st.number_input("udpInDatagrams", min_value=0)
                udpOutDatagrams = st.number_input("udpOutDatagrams", min_value=0)
                udpInErrors = st.number_input("udpInErrors", min_value=0)
            with col3:
                udpNoPorts = st.number_input("udpNoPorts", min_value=0)
                ipInReceives = st.number_input("ipInReceives", min_value=0)
                ipInDelivers = st.number_input("ipInDelivers", min_value=0)
                ipOutRequests = st.number_input("ipOutRequests", min_value=0)
                ipOutDiscards = st.number_input("ipOutDiscards", min_value=0)
                ipInDiscards = st.number_input("ipInDiscards", min_value=0)
                ipForwDatagrams = st.number_input("ipForwDatagrams", min_value=0)
                ipOutNoRoutes = st.number_input("ipOutNoRoutes", min_value=0)
                ipInAddrErrors = st.number_input("ipInAddrErrors", min_value=0)
                icmpInMsgs = st.number_input("icmpInMsgs", min_value=0)
                icmpInDestUnreachs = st.number_input("icmpInDestUnreachs", min_value=0)
                icmpOutMsgs = st.number_input("icmpOutMsgs", min_value=0)
                icmpOutDestUnreachs = st.number_input("icmpOutDestUnreachs", min_value=0)
                icmpInEchos = st.number_input("icmpInEchos", min_value=0)
            submit = st.form_submit_button("🚀 Lancer la prédiction")

        if submit:
            try:
                input_df = pd.DataFrame([{
                    "ifInOctets11": ifInOctets11, "ifOutOctets11": ifOutOctets11,
                    "ifoutDiscards11": ifoutDiscards11, "ifInUcastPkts11": ifInUcastPkts11,
                    "ifInNUcastPkts11": ifInNUcastPkts11, "ifInDiscards11": ifInDiscards11,
                    "ifOutUcastPkts11": ifOutUcastPkts11, "ifOutNUcastPkts11": ifOutNUcastPkts11,
                    "tcpOutRsts": tcpOutRsts, "tcpInSegs": tcpInSegs, "tcpOutSegs": tcpOutSegs,
                    "tcpPassiveOpens": tcpPassiveOpens, "tcpRetransSegs": tcpRetransSegs,
                    "tcpEstabResets": tcpEstabResets, "tcpCurrEstab": tcpCurrEstab,
                    "tcp?ActiveOpens": tcp_question_active_opens, "udpInDatagrams": udpInDatagrams,
                    "udpOutDatagrams": udpOutDatagrams, "udpInErrors": udpInErrors, "udpNoPorts": udpNoPorts,
                    "ipInReceives": ipInReceives, "ipInDelivers": ipInDelivers, "ipOutRequests": ipOutRequests,
                    "ipOutDiscards": ipOutDiscards, "ipInDiscards": ipInDiscards, "ipForwDatagrams": ipForwDatagrams,
                    "ipOutNoRoutes": ipOutNoRoutes, "ipInAddrErrors": ipInAddrErrors,
                    "icmpInMsgs": icmpInMsgs, "icmpInDestUnreachs": icmpInDestUnreachs,
                    "icmpOutMsgs": icmpOutMsgs, "icmpOutDestUnreachs": icmpOutDestUnreachs,
                    "icmpInEchos": icmpInEchos
                }])

                headers = {
                    "Authorization": f"Bearer {API_KEY}",
                    "DataRobot-Key": DATAROBOT_KEY,
                    "Content-Type": "text/csv"
                }
                response = requests.post(API_URL, headers=headers, data=input_df.to_csv(index=False))
                if response.status_code == 200:
                    pred = response.json()["data"][0]["prediction"]
                    score = dangerosite.get(pred, 50)
                    st.success(f"✅ Prédiction : **{pred}** | Dangerosité estimée : **{score}%**")
                    st.info(f"💡 Recommandation : {solutions.get(pred, 'Surveiller le trafic réseau.')}")
                    
                    if score > 70:
                        envoyer_alerte_email_mailjet(pred, score)

                    st.session_state["historique"] = pd.concat(
                        [st.session_state["historique"],
                         pd.DataFrame([{"Prediction": pred, "Dangerosité": score, "Horodatage": pd.Timestamp.now()}])],
                        ignore_index=True)
                else:
                    st.warning("❌ Impossible de prédire. Vérifiez vos données.")
            except:
                st.warning("⚠ Erreur réseau ou clé API invalide.")

    # ---- PRÉDICTION VIA CSV ----
    elif choix == "Prédiction via fichier CSV":
        fichier = st.file_uploader("📁 Importer un fichier CSV", type=["csv"])
        if fichier is not None:
            df = pd.read_csv(fichier)
            st.dataframe(df.head())
            if st.button("🚀 Envoyer à DataRobot"):
                try:
                    headers = {
                        "Authorization": f"Bearer {API_KEY}",
                        "DataRobot-Key": DATAROBOT_KEY,
                        "Content-Type": "text/csv"
                    }
                    response = requests.post(API_URL, headers=headers, data=df.to_csv(index=False))
                    if response.status_code == 200:
                        res = pd.json_normalize(response.json()["data"])
                        st.success("✅ Prédictions reçues")
                        st.dataframe(res[["rowId", "prediction"]])

                        horodatage = pd.Timestamp.now()
                        temp_hist = []
                        for _, row in res.iterrows():
                            pred = row["prediction"]
                            score = dangerosite.get(pred, 50)
                            temp_hist.append({"Prediction": pred, "Dangerosité": score, "Horodatage": horodatage})
                            if score > 70:
                                envoyer_alerte_email_mailjet(pred, score)
                        st.session_state["historique"] = pd.concat(
                            [st.session_state["historique"], pd.DataFrame(temp_hist)], ignore_index=True)
                except:
                    st.warning("⚠ Erreur réseau ou clé API invalide.")

# -------------------- ONGLET 2 : ANALYSE GLOBALE --------------------
with onglets[1]:
    st.subheader("📊 Analyse globale des prédictions")
    if st.session_state["historique"].empty:
        st.info("Aucune donnée disponible pour l'analyse.")
    else:
        df_hist = st.session_state["historique"]
        fig1 = px.histogram(df_hist, x="Prediction", color="Prediction", title="Répartition des types d'attaques")
        st.plotly_chart(fig1, use_container_width=True)

        fig2 = px.line(df_hist.sort_values("Horodatage"), x="Horodatage", y="Dangerosité",
                       title="Évolution du niveau de dangerosité", markers=True)
        st.plotly_chart(fig2, use_container_width=True)

        danger_moyen = df_hist["Dangerosité"].mean()
        jauge = go.Figure(go.Indicator(
            mode="gauge+number",
            value=danger_moyen,
            title={'text': "Niveau moyen de dangerosité (%)"},
            gauge={'axis': {'range': [0, 100]},
                   'bar': {'color': "red" if danger_moyen > 70 else "orange" if danger_moyen > 40 else "green"}}
        ))
        st.plotly_chart(jauge, use_container_width=True)

# -------------------- ONGLET 3 : HISTORIQUE --------------------
with onglets[2]:
    st.subheader("📜 Historique des prédictions")
    if st.session_state["historique"].empty:
        st.info("Aucune donnée enregistrée.")
    else:
        df_hist = st.session_state["historique"].sort_values(by="Horodatage", ascending=False)
        st.dataframe(df_hist)

        output_excel = BytesIO()
        df_hist.to_excel(output_excel, index=False, engine='openpyxl')
        st.download_button("📥 Télécharger en Excel", output_excel.getvalue(), "historique_predictions.xlsx")

        if st.button("📄 Générer le PDF"):
            pdf = FPDF()
            pdf.set_auto_page_break(auto=True, margin=15)
            pdf.add_page()
            pdf.set_font("Arial", 'B', 14)
            pdf.cell(0, 10, "Historique des Prédictions", ln=True, align="C")
            pdf.set_font("Arial", '', 10)
            pdf.ln(5)
            for _, row in df_hist.iterrows():
                pdf.cell(0, 8, f"{row['Horodatage']} | {row['Prediction']} | Dangerosité: {row['Dangerosité']}%", ln=True)
            pdf.output("historique.pdf")
            with open("historique.pdf", "rb") as f:
                st.download_button("📥 Télécharger en PDF", f.read(), "historique_predictions.pdf")

    if st.button("🗑️ Vider l'historique"):
        st.session_state["historique"] = pd.DataFrame(columns=["Prediction", "Dangerosité", "Horodatage"])
        st.success("✅ Historique vidé.")
