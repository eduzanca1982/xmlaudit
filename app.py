import streamlit as st
import pandas as pd
import plotly.express as px
import json
import re
from langchain_google_genai import ChatGoogleGenerativeAI
from langchain_core.messages import HumanMessage
from google.generativeai.types import HarmCategory, HarmBlockThreshold

# 1. CONFIGURACIÓN DE PÁGINA
st.set_page_config(
    page_title="WAF Auditor Pro | Security Analysis",
    page_icon="🛡️",
    layout="wide"
)

# 2. CARGA DE SECRETOS (GOOGLE_API_KEY)
try:
    # En Streamlit Cloud se configura en 'Settings' -> 'Secrets'
    # Formato: GOOGLE_API_KEY = "tu_clave"
    api_key = st.secrets["GOOGLE_API_KEY"]
except Exception:
    st.error("⚠️ Error: No se encontró la 'GOOGLE_API_KEY'. Configúrala en los Secrets de Streamlit.")
    st.stop()

# 3. ESTILOS CSS PARA MEJORAR LA UI
st.markdown("""
    <style>
    .stMetric { background-color: #f8f9fa; padding: 15px; border-radius: 10px; border: 1px solid #dee2e6; }
    .stAlert { border-radius: 10px; }
    </style>
    """, unsafe_allow_html=True)

# 4. FUNCIÓN CORE DE ANÁLISIS
def analyze_configurations(xml_content):
    # Configuramos los filtros de seguridad en BLOCK_NONE 
    # Esto es vital para que la IA no bloquee el análisis de ataques (SQLi, etc.)
    safety_settings = {
        HarmCategory.HARM_CATEGORY_HARASSMENT: HarmBlockThreshold.BLOCK_NONE,
        HarmCategory.HARM_CATEGORY_HATE_SPEECH: HarmBlockThreshold.BLOCK_NONE,
        HarmCategory.HARM_CATEGORY_SEXUALLY_EXPLICIT: HarmBlockThreshold.BLOCK_NONE,
        HarmCategory.HARM_CATEGORY_DANGEROUS_CONTENT: HarmBlockThreshold.BLOCK_NONE,
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

    IMPORTANTE: Al final de tu respuesta, añade estrictamente la sección "METRICAS_DATOS" seguida de un objeto JSON con este formato exacto para los gráficos:
    {{"Critico": X, "Alto": X, "Medio": X, "Bajo": X}}

    Responde en español con tono profesional y técnico.
    """

    response = llm.invoke([HumanMessage(content=prompt)])
    return response.content

# 5. INTERFAZ DE USUARIO
st.title("🛡️ WAF Policy Auditor Pro")
st.markdown("---")

col_info, col_upload = st.columns([1, 2])

with col_info:
    st.info("""
    **Capacidades:**
    - Auditoría de reglas Akamai/WAF.
    - Análisis de múltiples archivos XML.
    - Detección de brechas en App & API Protector.
    - Sugerencias de remediación inmediata.
    """)

with col_upload:
    uploaded_files = st.file_uploader(
        "Sube tus archivos XML de configuración", 
        type=["xml"], 
        accept_multiple_files=True
    )

# 6. PROCESAMIENTO
if uploaded_files:
    if st.button("🔍 Iniciar Auditoría Profunda", use_container_width=True):
        try:
            # Consolidar archivos
            combined_text = ""
            for f in uploaded_files:
                combined_text += f"\n--- ORIGEN: {f.name} ---\n{f.read().decode('utf-8')}\n"

            with st.spinner("Analizando telemetría y reglas con Gemini 1.5 Pro..."):
                full_response = analyze_configurations(combined_text)

                # Extraer JSON de métricas usando Regex para mayor robustez
                report_text = full_response.split("METRICAS_DATOS")[0]
                json_match = re.search(r'\{.*\}', full_response.split("METRICAS_DATOS")[-1], re.DOTALL)
                
                if json_match:
                    metrics = json.loads(json_match.group())
                else:
                    metrics = {"Critico": 0, "Alto": 0, "Medio": 0, "Bajo": 0}

                # --- DASHBOARD DE RESULTADOS ---
                st.subheader("📊 Resumen de Postura de Seguridad")
                m_col1, m_col2, m_col3, m_col4 = st.columns(4)
                m_col1.metric("Crítico", metrics.get("Critico", 0))
                m_col2.metric("Alto", metrics.get("Alto", 0))
                m_col3.metric("Medio", metrics.get("Medio", 0))
                m_col4.metric("Bajo", metrics.get("Bajo", 0))

                # Gráfico
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

                # Informe Detallado
                st.markdown("---")
                st.markdown("### 📋 Informe Técnico Detallado")
                st.markdown(report_text)

                # Descarga del reporte
                st.download_button(
                    label="💾 Descargar Informe de Auditoría",
                    data=report_text,
                    file_name="auditoria_waf_completa.md",
                    mime="text/markdown"
                )

        except Exception as e:
            st.error(f"Se produjo un error durante el análisis: {e}")
            st.warning("Tip: Verifica que el contenido de los XML no esté corrupto y que la API Key tenga cuota disponible.")

else:
    st.write("Esperando archivos para analizar...")
