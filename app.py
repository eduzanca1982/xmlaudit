import streamlit as st
import pandas as pd
import plotly.express as px
import json
import re
from langchain_google_genai import ChatGoogleGenerativeAI
from langchain_core.messages import HumanMessage

st.set_page_config(page_title="WAF/CDN Security Auditor", layout="wide")

try:
    api_key = st.secrets["GOOGLE_API_KEY"]
except:
    st.error("Falta GOOGLE_API_KEY en Secrets.")
    st.stop()

def optimize_xml(xml_content):
    xml_content = re.sub(r"", "", xml_content, flags=re.DOTALL)
    tags_ignorar = ["lastModifiedBy", "lastModifiedDate", "createDate", "createdBy"]
    for tag in tags_ignorar:
        xml_content = re.sub(f"<{tag}>.*?</{tag}>", "", xml_content, flags=re.DOTALL)
    return " ".join(xml_content.split())

def run_audit(content):
    safety_settings = {
        "HARM_CATEGORY_HARASSMENT": "BLOCK_NONE",
        "HARM_CATEGORY_HATE_SPEECH": "BLOCK_NONE",
        "HARM_CATEGORY_SEXUALLY_EXPLICIT": "BLOCK_NONE",
        "HARM_CATEGORY_DANGEROUS_CONTENT": "BLOCK_NONE",
    }

    llm = ChatGoogleGenerativeAI(
        model="gemini-2.5-pro", 
        google_api_key=api_key,
        temperature=0,
        safety_settings=safety_settings
    )
    
    prompt = f"""
    ERES: Auditor Senior de Ciberseguridad.
    OBJETIVO: Detectar FALLAS CRÍTICAS en configuraciones WAF y CDN de Akamai.
    
    ANALIZA EL XML BUSCANDO:
    1. SEGURIDAD WAF: Reglas críticas en 'Alert', bypass de protección, excepciones de IP sospechosas.
    2. CONFIGURACIÓN CDN: 
       - Cache Poisoning: Cabeceras mal configuradas.
       - TTLs: Cacheo de contenido sensible/personalizado.
       - Protocolos: Falta de HSTS, TLS obsoletos (1.0/1.1), o redirecciones HTTP mal implementadas.
       - Origin Pull: Fallas en la validación del certificado del origen.
    
    FORMATO DE RESPUESTA:
    - Lista directa de Fallas Detectadas.
    - Impacto Técnico.
    - Acción Correctiva Inmediata.
    
    IMPORTANTE: Finaliza con METRICAS_DATOS y el JSON:
    {{"Critico": X, "Alto": X, "Medio": X, "Bajo": X}}

    XML:
    {content}
    """
    
    return llm.invoke([HumanMessage(content=prompt)]).content

st.title("🛡️ Auditor de Fallas WAF & CDN")

files = st.file_uploader("Subir archivos XML", type="xml", accept_multiple_files=True)

if files:
    if st.button("🔍 Ejecutar Detección de Fallas"):
        try:
            full_raw_text = ""
            for f in files:
                full_raw_text += f.read().decode('utf-8')
            
            clean_text = optimize_xml(full_raw_text)

            with st.spinner("Analizando brechas de seguridad..."):
                response = run_audit(clean_text)
                
                parts = response.split("METRICAS_DATOS")
                report = parts[0]
                
                if len(parts) > 1:
                    json_str = re.search(r'\{.*\}', parts[1], re.DOTALL).group()
                    m = json.loads(json_str)
                    
                    c1, c2, c3, c4 = st.columns(4)
                    c1.metric("Crítico", m.get("Critico", 0))
                    c2.metric("Alto", m.get("Alto", 0))
                    c3.metric("Medio", m.get("Medio", 0))
                    c4.metric("Bajo", m.get("Bajo", 0))
                    
                    df = pd.DataFrame({"Nivel": list(m.keys()), "Fallas": list(m.values())})
                    fig = px.bar(df, x="Nivel", y="Fallas", color="Nivel", 
                                 color_discrete_map={"Critico": "black", "Alto": "#D32F2F", "Medio": "#F57C00", "Bajo": "#1976D2"})
                    st.plotly_chart(fig, use_container_width=True)

                st.markdown("### 🚫 Fallas de Seguridad Detectadas")
                st.markdown(report)

        except Exception as e:
            st.error(f"Error: {e}")
