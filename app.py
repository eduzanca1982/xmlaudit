import streamlit as st
import pandas as pd
import plotly.express as px
import json
import re
import time
from typing import Dict, List, Tuple

from langchain_google_genai import ChatGoogleGenerativeAI
from langchain_core.messages import HumanMessage

# Splitter: prefer the new package; fallback if user installed legacy langchain
try:
    from langchain_text_splitters import RecursiveCharacterTextSplitter  # type: ignore
except Exception:
    # Legacy fallback (only if langchain installed and provides it)
    try:
        from langchain.text_splitter import RecursiveCharacterTextSplitter  # type: ignore
    except Exception as e:
        raise ModuleNotFoundError(
            "No se pudo importar RecursiveCharacterTextSplitter. "
            "Instala langchain-text-splitters y usa el import recomendado."
        ) from e


# =========================
# PAGE
# =========================
st.set_page_config(page_title="WAF/CDN Security Auditor", layout="wide")
st.title("WAF/CDN Security Auditor (XML)")


# =========================
# SECRETS
# =========================
API_KEY = st.secrets.get("GOOGLE_API_KEY")
if not API_KEY:
    st.error("Falta GOOGLE_API_KEY en Secrets.")
    st.stop()


# =========================
# CONSTANTS
# =========================
DEFAULT_SAFETY_SETTINGS = {
    "HARM_CATEGORY_HARASSMENT": "BLOCK_NONE",
    "HARM_CATEGORY_HATE_SPEECH": "BLOCK_NONE",
    "HARM_CATEGORY_SEXUALLY_EXPLICIT": "BLOCK_NONE",
    "HARM_CATEGORY_DANGEROUS_CONTENT": "BLOCK_NONE",
}

METRICS_KEYS = ["Critico", "Alto", "Medio", "Bajo"]
METRICS_TEMPLATE = {"Critico": 0, "Alto": 0, "Medio": 0, "Bajo": 0}


# =========================
# UTILS
# =========================
def read_uploaded_file_as_text(f) -> str:
    raw = f.read()
    for enc in ("utf-8", "utf-8-sig", "latin-1"):
        try:
            return raw.decode(enc)
        except Exception:
            continue
    return raw.decode("utf-8", errors="replace")


def normalize_whitespace(s: str) -> str:
    s = s.replace("\r\n", "\n").replace("\r", "\n")
    s = re.sub(r"[ \t]+", " ", s)
    s = re.sub(r"\n{3,}", "\n\n", s)
    return s.strip()


def build_splitter(chunk_size: int, chunk_overlap: int) -> RecursiveCharacterTextSplitter:
    separators = [
        "\n<match-case",
        "\n<rule",
        "\n<policy",
        "\n<criteria",
        "\n<forward-server",
        "\n<condition",
        "\n<action",
        "\n</rule>",
        "\n</match-case>",
        "\n</policy>",
        "\n",
    ]
    return RecursiveCharacterTextSplitter(
        chunk_size=chunk_size,
        chunk_overlap=chunk_overlap,
        separators=separators,
    )


def mk_llm(model_name: str, temperature: float, safety_off: bool) -> ChatGoogleGenerativeAI:
    return ChatGoogleGenerativeAI(
        model=model_name,
        google_api_key=API_KEY,
        temperature=temperature,
        safety_settings=(DEFAULT_SAFETY_SETTINGS if safety_off else None),
    )


def audit_prompt(chunk: str, scope: str) -> str:
    focus = {
        "balanced": (
            "WAF (bypass/excepciones/alert-only/allowlists inseguras) y CDN/Edge "
            "(cache poisoning, caching de contenido sensible, cache-key/vary, TTLs, TLS/HSTS, redirects, origin exposure)."
        ),
        "waf": (
            "WAF (alert-only, bypass, excepciones amplias, ignores peligrosos, allow/deny, rate controls, bot/headers)."
        ),
        "cdn": (
            "CDN/Edge (caching de contenido sensible, TTLs, cache key, vary, querystring handling, redirects, TLS/HSTS, origin exposure, forwarding)."
        ),
    }.get(scope, "WAF y CDN/Edge.")

    # Output contract: bullets only + sentinel JSON
    return f"""
ROL: Auditor senior de ciberseguridad (Akamai WAF/CDN).
TAREA: Detectar fallas y mejoras concretas desde el XML.

ENFOQUE:
- {focus}

REGLAS DE SALIDA (OBLIGATORIAS):
1) SOLO bullets. Sin prosa. Sin introducciones.
2) Formato exacto por bullet:
   - [NIVEL] Hallazgo :: Impacto :: Fix (acción específica)
   NIVEL ∈ {{CRITICO, ALTO, MEDIO, BAJO}}
3) No inventes features. Ancla cada hallazgo al XML (tag/atributo/valor).
4) Si depende de contexto no visible, escribir "Asunción" y NO usar CRITICO.
5) Al final, SIEMPRE:

METRICAS_DATOS
{json.dumps(METRICS_TEMPLATE, ensure_ascii=False)}
FIN_METRICAS

XML:
{chunk}
""".strip()


def extract_json_metrics(model_text: str) -> Dict[str, int]:
    out = {k: 0 for k in METRICS_KEYS}

    m = re.search(r"METRICAS_DATOS\s*(\{.*?\})\s*FIN_METRICAS", model_text, flags=re.DOTALL)
    candidate = m.group(1) if m else None

    if not candidate:
        # salvage: last JSON object containing any key
        objs = re.findall(r"\{.*?\}", model_text, flags=re.DOTALL)
        for obj in reversed(objs):
            if any(k in obj for k in METRICS_KEYS):
                candidate = obj
                break

    if not candidate:
        return out

    try:
        data = json.loads(candidate)
        for k in METRICS_KEYS:
            v = data.get(k, 0)
            if isinstance(v, (int, float)) and v >= 0:
                out[k] = int(v)
    except Exception:
        pass

    return out


def strip_metrics_block(model_text: str) -> str:
    return re.sub(r"METRICAS_DATOS.*?FIN_METRICAS", "", model_text, flags=re.DOTALL).strip()


def invoke_with_retries(llm: ChatGoogleGenerativeAI, prompt: str, max_retries: int = 3) -> str:
    last_err = None
    for attempt in range(max_retries):
        try:
            return llm.invoke([HumanMessage(content=prompt)]).content or ""
        except Exception as e:
            last_err = e
            time.sleep(1.25 * (attempt + 1))
    raise last_err


def run_audit_chunked(
    content: str,
    model_name: str,
    temperature: float,
    safety_off: bool,
    scope: str,
    chunk_size: int,
    chunk_overlap: int,
) -> Tuple[str, Dict[str, int], List[Dict]]:
    llm = mk_llm(model_name=model_name, temperature=temperature, safety_off=safety_off)
    splitter = build_splitter(chunk_size=chunk_size, chunk_overlap=chunk_overlap)
    chunks = splitter.split_text(content)

    total_metrics = {k: 0 for k in METRICS_KEYS}
    reports: List[str] = []
    per_chunk: List[Dict] = []

    progress = st.progress(0)
    status = st.empty()

    for i, chunk in enumerate(chunks):
        status.write(f"Analizando chunk {i+1}/{len(chunks)} (chars={len(chunk):,})")

        try:
            prompt = audit_prompt(chunk, scope=scope)
            resp = invoke_with_retries(llm, prompt, max_retries=3)

            m = extract_json_metrics(resp)
            for k in METRICS_KEYS:
                total_metrics[k] += m.get(k, 0)

            clean = strip_metrics_block(resp)
            if clean:
                reports.append(clean)

            per_chunk.append(
                {"chunk_index": i, "chunk_chars": len(chunk), "metrics": m, "ok": True}
            )

        except Exception as e:
            # No matamos el proceso por un chunk fallido
            reports.append(f"- [MEDIO] Chunk error :: Fallo al procesar chunk {i+1} :: Fix: revisar logs/limitar chunk_size (error: {e})")
            per_chunk.append(
                {"chunk_index": i, "chunk_chars": len(chunk), "metrics": METRICS_TEMPLATE, "ok": False, "error": str(e)}
            )

        progress.progress((i + 1) / max(1, len(chunks)))

    status.empty()
    return "\n\n".join(reports), total_metrics, per_chunk


# =========================
# UI
# =========================
with st.sidebar:
    st.subheader("Entrada")
    input_mode = st.radio("Modo", ["Archivos XML", "Texto XML"], index=0)

    st.subheader("Modelo")
    model_name = st.selectbox("Modelo", ["gemini-2.5-flash", "gemini-2.5-pro", "gemini-2.0-flash"], index=0)
    temperature = st.slider("Temperature", 0.0, 0.5, 0.0, 0.05)

    st.subheader("Scope")
    scope = st.selectbox("Focus", ["balanced", "waf", "cdn"], index=0)

    st.subheader("Chunking")
    chunk_size = st.number_input("chunk_size (chars)", min_value=50_000, max_value=500_000, value=180_000, step=10_000)
    chunk_overlap = st.number_input("chunk_overlap (chars)", min_value=0, max_value=80_000, value=12_000, step=1_000)

    st.subheader("Robustez")
    safety_off = st.checkbox("Safety OFF", value=True)
    normalize = st.checkbox("Normalizar whitespace", value=True)

tab_exec, tab_tech = st.tabs(["Executive", "Técnico"])

xml_text = ""

with tab_exec:
    st.subheader("Carga XML")

    if input_mode == "Archivos XML":
        files = st.file_uploader("Subir XML", type="xml", accept_multiple_files=True)
        if files:
            xml_text = "\n\n".join(read_uploaded_file_as_text(f) for f in files)
    else:
        xml_text = st.text_area("Pegar XML", height=260, placeholder="<policy>...</policy>")

    if xml_text:
        if normalize:
            xml_text = normalize_whitespace(xml_text)

        run = st.button("Iniciar auditoría", type="primary", use_container_width=True)
        if run:
            with st.spinner("Procesando..."):
                report, metrics, per_chunk = run_audit_chunked(
                    content=xml_text,
                    model_name=model_name,
                    temperature=temperature,
                    safety_off=safety_off,
                    scope=scope,
                    chunk_size=int(chunk_size),
                    chunk_overlap=int(chunk_overlap),
                )

            k1, k2, k3, k4 = st.columns(4)
            k1.metric("Crítico", metrics["Critico"])
            k2.metric("Alto", metrics["Alto"])
            k3.metric("Medio", metrics["Medio"])
            k4.metric("Bajo", metrics["Bajo"])

            df = pd.DataFrame({"Nivel": list(metrics.keys()), "Fallas": list(metrics.values())})
            fig = px.bar(df, x="Nivel", y="Fallas", color="Nivel")
            st.plotly_chart(fig, use_container_width=True)

            st.subheader("Hallazgos")
            st.markdown(report if report.strip() else "- Sin hallazgos detectables con el XML provisto.")

            export = {
                "model": model_name,
                "scope": scope,
                "metrics": metrics,
                "chunks": per_chunk,
            }
            st.download_button(
                "Descargar JSON",
                data=json.dumps(export, ensure_ascii=False, indent=2).encode("utf-8"),
                file_name="audit_output.json",
                mime="application/json",
                use_container_width=True,
            )

            st.session_state["last_report_md"] = report
            st.session_state["last_export"] = export


with tab_tech:
    st.subheader("Debug")
    export = st.session_state.get("last_export")
    if not export:
        st.info("Ejecuta una auditoría para ver debug.")
    else:
        st.json({"model": export["model"], "scope": export["scope"], "metrics": export["metrics"], "chunks": len(export["chunks"])})

        idx = st.number_input("Chunk index", min_value=0, max_value=max(0, len(export["chunks"]) - 1), value=0, step=1)
        st.json(export["chunks"][int(idx)])

        st.download_button(
            "Descargar reporte Markdown",
            data=(st.session_state.get("last_report_md", "") or "").encode("utf-8"),
            file_name="audit_report.md",
            mime="text/markdown",
        )
