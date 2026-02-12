import streamlit as st
import pandas as pd
import plotly.express as px
import json
import re
from langchain_google_genai import ChatGoogleGenerativeAI
from langchain_core.messages import HumanMessage

# 1. CONFIGURACIÓN DE PÁGINA
st.set_page_config(
    page_title="WAF Auditor Pro | Security Analysis",
    page_icon="🛡️",
    layout="wide"
)

# 2. CARGA DE SECRETOS (GOOGLE_API_KEY)
try:
    api_key = st.secrets["GOOGLE_API_KEY"]
except Exception:
    st.error("⚠️ Error: No se encontró la 'GOOGLE_API_KEY' en Secrets.")
    st.stop()

# 3. ESTILOS CSS
st.markdown("""
    <style>
    .stMetric { background-color: #f8f9fa; padding: 15px; border-radius: 10px; border: 1px solid #dee2e6; }
    </style>
    """, unsafe_allow_html=True)

# 4. FUNCIÓN DE ANÁLISIS
def analyze_configurations(xml_content):
    # Definición de seguridad usando STRINGS para evitar errores de validación Pydantic
    safety_settings = {
        "HARM_CATEGORY_HARASSMENT": "BLOCK_NONE",
        "HARM_CATEGORY_HATE_SPEECH": "BLOCK_NONE",
        "HARM_CATEGORY_SEXUALLY_EXPLICIT": "BLOCK_NONE",
        "HARM_CATEGORY_DANGEROUS_CONTENT": "BLOCK_NONE",
    }

    llm = ChatGoogleGenerativeAI(
        model="gemini-1.5-pro",
        google_api_key=api_key,
        temperature=0.1,
        safety_settings=safety_settings
    )
    
    prompt = f"""
    Actúa como un Senior Security Engineer experto en Akamai App & API Protector.
    Analiza el siguiente contenido XML de políticas WAF:

    {xml_content}

    TAREAS:
    1. Identifica configuraciones inseguras (ej. reglas críticas en modo ALERT en lugar de DENY).
    2. Detecta oportunidades de mejora en la postura de seguridad y optimización de reglas de Bot Manager.
    3. Encuentra posibles falsos positivos basados en las excepciones configuradas.
    4. Genera una tabla de hallazgos con Criticidad, Descripción y Recomendación.

    IMPORTANTE: Al final de tu respuesta, añade la sección "METRICAS_DATOS" seguida de un objeto JSON con este formato exacto:
    {{"Critico": X, "Alto": X, "Medio": X, "Bajo": X}}

    Responde en español con tono profesional.
    """

    response = llm.invoke([HumanMessage(content=prompt)])
    return response.content

# 5. INTERFAZ
st.title("🛡️ WAF Policy Auditor Pro")
st.markdown("---")

col_info, col_upload = st.columns([1, 2])

with col_info:
    st.info("""
    **Análisis Técnico:**
    - Auditoría de reglas Akamai.
    - Soporte multi-archivo XML.
    - Detección de brechas en App & API Protector.
    """)

with col_upload:
    uploaded_files = st.file_uploader(
        "Sube archivos XML de configuración", 
        type=["xml"], 
        accept_multiple_files=True
    )

if uploaded_files:
    if st.button("🔍 Iniciar Auditoría Profunda", use_container_width=True):
        try:
            combined_text = ""
            for f in uploaded_files:
                combined_text += f"\n--- ORIGEN: {f.name} ---\n{f.read().decode('utf-8')}\n"

            with st.spinner("Gemini analizando reglas de seguridad..."):
                full_response = analyze_configurations(combined_text)

                # Parsing de respuesta y JSON
                report_text = full_response.split("METRICAS_DATOS")[0]
                json_match = re.search(r'\{.*\}', full_response.split("METRICAS_DATOS")[-1], re.DOTALL)
                
                metrics = json.loads(json_match.group()) if json_match else {"Critico": 0, "Alto": 0, "Medio": 0, "Bajo": 0}

                # Dashboard
                st.subheader("📊 Resumen de Postura de Seguridad")
                m_col1, m_col2, m_col3, m_col4 = st.columns(4)
                m_col1.metric("Crítico", metrics.get("Critico", 0))
                m_col2.metric("Alto", metrics.get("Alto", 0))
                m_col3.metric("Medio", metrics.get("Medio", 0))
                m_col4.metric("Bajo", metrics.get("Bajo", 0))

                # Gráfico con Plotly
                df_plot = pd.DataFrame({
                    "Nivel": list(metrics.keys()),
                    "Cantidad": list(metrics.values())
                })
                fig = px.bar(
                    df_plot, x="Nivel", y="Cantidad", 
                    color="Nivel",
                    color_discrete_map={"Critico": "#000000", "Alto": "#FF4B4B", "Medio": "#FFA500", "Bajo": "#1F77B4"}
                )
                st.plotly_chart(fig, use_container_width=True)

                st.markdown("---")
                st.markdown("### 📋 Informe Técnico Detallado")
                st.markdown(report_text)

                st.download_button(
                    label="💾 Descargar Informe",
                    data=report_text,
                    file_name="auditoria_waf.md"
                )

        except Exception as e:
            st.error(f"Error técnico: {e}")
