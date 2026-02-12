import streamlit as st
import pandas as pd
import plotly.express as px
import json
import re
from langchain_google_genai import ChatGoogleGenerativeAI
from langchain_core.messages import HumanMessage

st.set_page_config(page_title="WAF Auditor 2.5 Pro", layout="wide", page_icon="🛡️")

# 1. CARGA DE API KEY
try:
    api_key = st.secrets["GOOGLE_API_KEY"]
except:
    st.error("Error: Configura GOOGLE_API_KEY en Secrets.")
    st.stop()

# 2. FUNCIÓN DE LIMPIEZA TÉCNICA (REDUCCIÓN DE TOKENS)
def optimize_xml(xml_content):
    # Eliminar comentarios
    xml_content = re.sub(r"", "", xml_content, flags=re.DOTALL)
    # Eliminar metadata de Akamai que no influye en seguridad (ahorra ~15% de tokens)
    tags_ignorar = ["lastModifiedBy", "lastModifiedDate", "createDate", "createdBy", "systemMetadata"]
    for tag in tags_ignorar:
        xml_content = re.sub(f"<{tag}>.*?</{tag}>", "", xml_content, flags=re.DOTALL)
    # Minificar: quitar espacios en blanco innecesarios
    return " ".join(xml_content.split())

# 3. LÓGICA DE AUDITORÍA
def run_audit(content):
    safety_settings = {
        "HARM_CATEGORY_HARASSMENT": "BLOCK_NONE",
        "HARM_CATEGORY_HATE_SPEECH": "BLOCK_NONE",
        "HARM_CATEGORY_SEXUALLY_EXPLICIT": "BLOCK_NONE",
        "HARM_CATEGORY_DANGEROUS_CONTENT": "BLOCK_NONE",
    }

    # Usamos Gemini 2.5 Pro para máxima ventana de contexto
    llm = ChatGoogleGenerativeAI(
        model="gemini-2.5-pro", 
        google_api_key=api_key,
        temperature=0,
        safety_settings=safety_settings
    )
    
    prompt = f"""
    ERES: Senior Security Engineer / Akamai Specialist.
    CONTEXTO: Se adjuntan políticas WAF en formato XML.
    
    TAREAS:
    1. Detectar reglas críticas en modo 'Alert' que deberían estar en 'Deny'.
    2. Identificar inconsistencias en la configuración de Bot Manager.
    3. Listar oportunidades de mejora para endurecer (harden) la postura de seguridad.
    
    IMPORTANTE: Finaliza con la sección METRICAS_DATOS y el JSON:
    {{"Critico": X, "Alto": X, "Medio": X, "Bajo": X}}

    POLÍTICAS:
    {content}
    """
    
    return llm.invoke([HumanMessage(content=prompt)]).content

# 4. INTERFAZ STREAMLIT
st.title("🛡️ WAF Policy Auditor Pro (Gemini 2.5)")

files = st.file_uploader("Sube archivos XML (Akamai WAF)", type="xml", accept_multiple_files=True)

if files:
    if st.button("🚀 Iniciar Análisis de Gran Escala"):
        try:
            full_raw_text = ""
            for f in files:
                full_raw_text += f.read().decode('utf-8')
            
            # Optimización previa
            with st.status("Optimizando XML y reduciendo tokens...") as status:
                clean_text = optimize_xml(full_raw_text)
                st.write(f"Tokens originales estimados: {len(full_raw_text)//4}")
                st.write(f"Tokens tras optimización: {len(clean_text)//4}")
                status.update(label="Análisis optimizado listo. Enviando a Gemini 2.5 Pro...", state="complete")

            with st.spinner("Gemini 2.5 Pro analizando configuración masiva..."):
                response = run_audit(clean_text)
                
                # Separación de Informe y Métricas
                parts = response.split("METRICAS_DATOS")
                report = parts[0]
                
                # Visualización de métricas
                if len(parts) > 1:
                    json_str = re.search(r'\{.*\}', parts[1], re.DOTALL).group()
                    m = json.loads(json_str)
                    
                    c1, c2, c3, c4 = st.columns(4)
                    c1.metric("Crítico", m.get("Critico", 0))
                    c2.metric("Alto", m.get("Alto", 0))
                    c3.metric("Medio", m.get("Medio", 0))
                    c4.metric("Bajo", m.get("Bajo", 0))
                    
                    df = pd.DataFrame({"Nivel": list(m.keys()), "Hallazgos": list(m.values())})
                    fig = px.bar(df, x="Nivel", y="Hallazgos", color="Nivel", 
                                 color_discrete_map={"Critico": "black", "Alto": "red", "Medio": "orange", "Bajo": "blue"})
                    st.plotly_chart(fig)

                st.markdown("### 📋 Informe de Seguridad")
                st.markdown(report)

        except Exception as e:
            st.error(f"Error en el proceso: {e}")
