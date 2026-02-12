import streamlit as st
import pandas as pd
import plotly.express as px
import json
import re
from langchain_google_genai import ChatGoogleGenerativeAI
from langchain_core.messages import HumanMessage
from langchain.text_splitter import RecursiveCharacterTextSplitter

st.set_page_config(page_title="WAF/CDN Security Auditor", layout="wide")

try:
    api_key = st.secrets["GOOGLE_API_KEY"]
except:
    st.error("Falta GOOGLE_API_KEY en Secrets.")
    st.stop()

def run_audit_chunked(content):
    safety_settings = {
        "HARM_CATEGORY_HARASSMENT": "BLOCK_NONE",
        "HARM_CATEGORY_HATE_SPEECH": "BLOCK_NONE",
        "HARM_CATEGORY_SEXUALLY_EXPLICIT": "BLOCK_NONE",
        "HARM_CATEGORY_DANGEROUS_CONTENT": "BLOCK_NONE",
    }

    # Usamos Flash para los chunks por velocidad y costo, o Pro si prefieres profundidad
    llm = ChatGoogleGenerativeAI(
        model="gemini-2.5-flash", 
        google_api_key=api_key,
        temperature=0,
        safety_settings=safety_settings
    )

    # Dividimos el XML en pedazos de ~800k tokens para dejar margen de seguridad
    # Un token son aprox 4 caracteres en inglés/código
    text_splitter = RecursiveCharacterTextSplitter(
        chunk_size=3000000, # Caracteres, no tokens
        chunk_overlap=50000,
        separators=["<rule>", "<match-case>", "<forward-server>", "\n"]
    )
    chunks = text_splitter.split_text(content)
    
    all_reports = []
    total_metrics = {"Critico": 0, "Alto": 0, "Medio": 0, "Bajo": 0}

    progress_bar = st.progress(0)
    for i, chunk in enumerate(chunks):
        st.write(f"Analizando fragmento {i+1} de {len(chunks)}...")
        
        prompt = f"""
        ERES: Auditor Senior de Ciberseguridad.
        OBJETIVO: Detectar FALLAS CRÍTICAS en configuraciones WAF y CDN de Akamai.
        
        ANALIZA ESTE FRAGMENTO DE XML:
        1. WAF: Reglas en 'Alert', bypass, excepciones inseguras.
        2. CDN: Cache Poisoning, TTLs sensibles, protocolos TLS viejos, fallas en HSTS.
        
        FORMATO:
        - Lista directa de Fallas.
        - Impacto y Acción Correctiva.
        
        Finaliza con METRICAS_DATOS y el JSON:
        {{"Critico": X, "Alto": X, "Medio": X, "Bajo": X}}

        XML:
        {chunk}
        """
        
        response = llm.invoke([HumanMessage(content=prompt)]).content
        
        # Extraer métricas de este chunk y sumarlas
        parts = response.split("METRICAS_DATOS")
        all_reports.append(parts[0])
        
        if len(parts) > 1:
            try:
                json_str = re.search(r'\{.*\}', parts[1], re.DOTALL).group()
                m = json.loads(json_str)
                for key in total_metrics:
                    total_metrics[key] += m.get(key, 0)
            except:
                pass
        
        progress_bar.progress((i + 1) / len(chunks))

    return "\n".join(all_reports), total_metrics

# --- INTERFAZ ---
st.title("🛡️ Auditor de Fallas WAF & CDN (Contexto Extendido)")

files = st.file_uploader("Subir archivos XML", type="xml", accept_multiple_files=True)

if files:
    if st.button("🔍 Iniciar Auditoría"):
        try:
            full_text = "".join([f.read().decode('utf-8') for f in files])
            
            # Limpieza básica de espacios para ahorrar algo de espacio inicial
            full_text = " ".join(full_text.split())

            with st.spinner("Procesando archivos masivos..."):
                report, metrics = run_audit_chunked(full_text)
                
                # Visualización
                c1, c2, c3, c4 = st.columns(4)
                c1.metric("Crítico", metrics["Critico"])
                c2.metric("Alto", metrics["Alto"])
                c3.metric("Medio", metrics["Medio"])
                c4.metric("Bajo", metrics["Bajo"])
                
                df = pd.DataFrame({"Nivel": list(metrics.keys()), "Fallas": list(metrics.values())})
                fig = px.bar(df, x="Nivel", y="Fallas", color="Nivel", 
                             color_discrete_map={"Critico": "black", "Alto": "#D32F2F", "Medio": "#F57C00", "Bajo": "#1976D2"})
                st.plotly_chart(fig, use_container_width=True)

                st.markdown("### 🚫 Fallas de Seguridad Detectadas")
                st.markdown(report)

        except Exception as e:
            st.error(f"Error: {e}")
