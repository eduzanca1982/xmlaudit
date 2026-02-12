import streamlit as st
import pandas as pd
import plotly.express as px
from langchain_google_genai import ChatGoogleGenerativeAI
from langchain_core.messages import HumanMessage
import json

# Configuración inicial
st.set_page_config(page_title="WAF Auditor Pro", layout="wide", page_icon="🛡️")

# Acceso al API Key vía Secrets
try:
    api_key = st.secrets["GOOGLE_API_KEY"]
except:
    st.error("Error: Configura GOOGLE_API_KEY en los Secrets de Streamlit.")
    st.stop()

# Estilos personalizados para métricas
st.markdown("""
    <style>
    .reportview-container .main .block-container { padding-top: 1rem; }
    .stMetric { background-color: #f0f2f6; padding: 10px; border-radius: 10px; }
    </style>
    """, unsafe_allow_html=True)

st.title("🛡️ WAF & Akamai Security Auditor")
st.subheader("Análisis técnico de políticas y detección de brechas")

# Upload de archivos
files = st.file_uploader("Sube archivos de configuración XML", type=["xml"], accept_multiple_files=True)

def get_ai_analysis(xml_content):
    llm = ChatGoogleGenerativeAI(model="gemini-1.5-pro", google_api_key=api_key, temperature=0)
    
    # Prompt de dos partes: una para el informe y otra para datos estructurados (JSON)
    prompt = f"""
    Eres un experto en Akamai y seguridad de aplicaciones. Analiza estos archivos XML:
    
    {xml_content}
    
    TAREA:
    1. Genera un informe detallado con:
       - Riesgos detectados (SQLi, XSS, Bots, etc.)
       - Oportunidades de mejora (configuraciones 'Alert' a 'Deny', optimización de reglas).
       - Falsos positivos potenciales.
    2. Al final de tu respuesta, incluye una sección llamada "METRICAS_JSON" que sea estrictamente un objeto JSON con el conteo de hallazgos por severidad:
       {{"Crítico": X, "Alto": X, "Medio": X, "Bajo": X}}
    
    Responde en Markdown profesional.
    """
    
    response = llm.invoke([HumanMessage(content=prompt)])
    return response.content

if files:
    if st.button("🚀 Ejecutar Auditoría Profunda"):
        # Leer y combinar archivos
        combined_xml = ""
        for f in files:
            combined_xml += f"\n--- {f.name} ---\n{f.read().decode('utf-8')}\n"
        
        with st.spinner("Gemini analizando patrones de ataque y políticas..."):
            raw_result = get_ai_analysis(combined_xml)
            
            # Separar el informe del JSON de métricas
            try:
                report_part = raw_result.split("METRICAS_JSON")[0]
                json_part = raw_result.split("METRICAS_JSON")[1].strip()
                # Limpiar posibles caracteres de formato de Gemini
                json_part = json_part.replace("```json", "").replace("```", "").strip()
                metrics = json.loads(json_part)
            except:
                report_part = raw_result
                metrics = {"Crítico": 0, "Alto": 0, "Medio": 0, "Bajo": 0}

            # --- VISUALIZACIÓN DE RESULTADOS ---
            
            # 1. Dashboard de Métricas
            cols = st.columns(4)
            cols[0].metric("Crítico", metrics.get("Crítico", 0), delta_color="inverse")
            cols[1].metric("Alto", metrics.get("Alto", 0))
            cols[2].metric("Medio", metrics.get("Medio", 0))
            cols[3].metric("Bajo", metrics.get("Bajo", 0))

            # 2. Gráfico de Severidad
            df_metrics = pd.DataFrame({
                "Nivel": list(metrics.keys()),
                "Hallazgos": list(metrics.values())
            })
            fig = px.bar(df_metrics, x="Nivel", y="Hallazgos", color="Nivel",
                         color_discrete_map={"Crítico": "black", "Alto": "red", "Medio": "orange", "Bajo": "blue"},
                         title="Distribución de Riesgos Detectados")
            st.plotly_chart(fig, use_container_width=True)

            # 3. Informe Detallado
            st.divider()
            st.markdown("### 📋 Informe Técnico y Oportunidades de Mejora")
            st.markdown(report_part)
            
            # Botón de descarga
            st.download_button("Descargar Reporte Completo", report_part, "auditoria_seguridad.md")

else:
    st.info("💡 Tip: Puedes subir múltiples versiones de una misma política para que la IA detecte cambios o degradación de seguridad.")
