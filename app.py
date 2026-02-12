import streamlit as st
import pandas as pd
import plotly.express as px
import json
import re
import time
from typing import Dict, List, Tuple, Optional

from langchain_google_genai import ChatGoogleGenerativeAI
from langchain_core.messages import HumanMessage
from langchain.text_splitter import RecursiveCharacterTextSplitter


# =========================
# CONFIG / PAGE
# =========================
st.set_page_config(page_title="WAF/CDN Security Auditor", layout="wide")

st.title("WAF/CDN Security Auditor (XML)")

try:
    API_KEY = st.secrets["GOOGLE_API_KEY"]
except Exception:
    st.error("Falta GOOGLE_API_KEY en Secrets.")
    st.stop()


# =========================
# HELPERS
# =========================
DEFAULT_SAFETY_SETTINGS = {
    "HARM_CATEGORY_HARASSMENT": "BLOCK_NONE",
    "HARM_CATEGORY_HATE_SPEECH": "BLOCK_NONE",
    "HARM_CATEGORY_SEXUALLY_EXPLICIT": "BLOCK_NONE",
    "HARM_CATEGORY_DANGEROUS_CONTENT": "BLOCK_NONE",
}

JSON_SCHEMA_HINT = {
    "Critico": 0,
    "Alto": 0,
    "Medio": 0,
    "Bajo": 0,
}

METRICS_KEYS = ["Critico", "Alto", "Medio", "Bajo"]


def _read_uploaded_file_as_text(f) -> str:
    """
    Robust decoding: try utf-8, utf-8-sig, latin-1 fallback.
    """
    raw = f.read()
    for enc in ("utf-8", "utf-8-sig", "latin-1"):
        try:
            return raw.decode(enc)
        except Exception:
            continue
    # last resort: replace errors
    return raw.decode("utf-8", errors="replace")


def _normalize_whitespace(s: str) -> str:
    # Reduce only excessive whitespace; keep tag boundaries readable.
    s = s.replace("\r\n", "\n").replace("\r", "\n")
    # Collapse runs of spaces/tabs (not newlines)
    s = re.sub(r"[ \t]+", " ", s)
    # Collapse many blank lines
    s = re.sub(r"\n{3,}", "\n\n", s)
    return s.strip()


def _build_splitter(chunk_size: int, chunk_overlap: int) -> RecursiveCharacterTextSplitter:
    """
    Chunking tuned for XML configs / policies.
    """
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


def _extract_json_metrics(model_text: str) -> Dict[str, int]:
    """
    Parse metrics JSON from a strict sentinel block. Accept a few formats safely.
    Expected somewhere near the end:
      METRICAS_DATOS
      {...json...}
      FIN_METRICAS

    If the model deviates, we attempt to salvage the *last* JSON object containing the expected keys.
    """
    # Preferred: sentinel-bounded
    m = re.search(r"METRICAS_DATOS\s*(\{.*?\})\s*FIN_METRICAS", model_text, flags=re.DOTALL)
    candidate = None
    if m:
        candidate = m.group(1)
    else:
        # Fallback: last JSON object in text
        objs = re.findall(r"\{.*?\}", model_text, flags=re.DOTALL)
        # choose last that contains at least one key
        for obj in reversed(objs):
            if any(k in obj for k in METRICS_KEYS):
                candidate = obj
                break

    out = {k: 0 for k in METRICS_KEYS}
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


def _strip_metrics_block(model_text: str) -> str:
    """
    Remove metrics block to keep report clean.
    """
    model_text = re.sub(r"METRICAS_DATOS.*?FIN_METRICAS", "", model_text, flags=re.DOTALL).strip()
    return model_text


def _mk_llm(model_name: str, temperature: float, safety_off: bool) -> ChatGoogleGenerativeAI:
    return ChatGoogleGenerativeAI(
        model=model_name,
        google_api_key=API_KEY,
        temperature=temperature,
        safety_settings=(DEFAULT_SAFETY_SETTINGS if safety_off else None),
    )


def _audit_prompt(chunk: str, mode: str) -> str:
    """
    mode: 'balanced' (WAF+CDN) | 'waf' | 'cdn'
    """
    focus = {
        "balanced": (
            "WAF (bypass/excepciones/alert-only/allowlists inseguras) y CDN (cache poisoning, caching de contenido sensible, "
            "headers de seguridad, TLS, HSTS, redirects, origin exposure, forward/proxy)."
        ),
        "waf": (
            "WAF (alert-only, bypass, excepciones amplias, ignores peligrosos, match conditions débiles, allow/deny, rate controls, bot/headers)."
        ),
        "cdn": (
            "CDN/Edge (caching de contenido sensible, TTLs, cache key, vary, querystring handling, redirects, TLS/HSTS, origin exposure, forwarding)."
        ),
    }[mode]

    # For robustness: enforce strict output contract with sentinels and JSON schema.
    return f"""
ROL: Auditor senior de ciberseguridad (Akamai WAF/CDN).
TAREA: Detectar fallas y mejoras concretas a partir del XML provisto.

ENFOQUE:
- {focus}

REGLAS DE SALIDA (OBLIGATORIAS):
1) Devuelve SOLO bullets, sin prosa.
2) Cada bullet debe tener este formato exacto:
   - [NIVEL] Hallazgo :: Impacto :: Fix (acción específica)
   Donde NIVEL ∈ {{CRITICO, ALTO, MEDIO, BAJO}}.
3) Si un hallazgo depende de contexto no visible en el XML, indícalo como "Asunción" y baja el nivel (no CRITICO).
4) No inventes features; cita el fragmento mínimo (tag/atributo/valor) que te disparó el hallazgo.
5) Al final, agrega métricas con sentinels EXACTOS:

METRICAS_DATOS
{json.dumps(JSON_SCHEMA_HINT, ensure_ascii=False)}
FIN_METRICAS

XML (fragmento):
{chunk}
""".strip()


def _invoke_with_retries(llm: ChatGoogleGenerativeAI, prompt: str, max_retries: int = 3) -> str:
    """
    Simple retry with backoff for transient API errors.
    """
    last_err = None
    for attempt in range(max_retries):
        try:
            return llm.invoke([HumanMessage(content=prompt)]).content or ""
        except Exception as e:
            last_err = e
            time.sleep(1.5 * (attempt + 1))
    raise last_err


def run_audit_chunked(
    content: str,
    model_name: str,
    temperature: float,
    safety_off: bool,
    mode: str,
    chunk_size: int,
    chunk_overlap: int,
) -> Tuple[str, Dict[str, int], List[Dict]]:
    """
    Returns:
      report_md: string markdown
      total_metrics: dict
      raw_chunks: list of per-chunk objects (for debugging / export)
    """
    llm = _mk_llm(model_name=model_name, temperature=temperature, safety_off=safety_off)
    splitter = _build_splitter(chunk_size=chunk_size, chunk_overlap=chunk_overlap)
    chunks = splitter.split_text(content)

    total_metrics = {k: 0 for k in METRICS_KEYS}
    all_reports: List[str] = []
    raw_chunks: List[Dict] = []

    progress = st.progress(0)
    status = st.empty()

    for i, chunk in enumerate(chunks):
        status.write(f"Analizando fragmento {i+1} de {len(chunks)} (chars={len(chunk):,})")
        prompt = _audit_prompt(chunk=chunk, mode=mode)

        response = _invoke_with_retries(llm, prompt, max_retries=3)

        m = _extract_json_metrics(response)
        for k in METRICS_KEYS:
            total_metrics[k] += int(m.get(k, 0))

        clean = _strip_metrics_block(response)
        all_reports.append(clean)

        raw_chunks.append(
            {
                "chunk_index": i,
                "chunk_chars": len(chunk),
                "metrics": m,
                "report": clean,
            }
        )

        progress.progress((i + 1) / max(1, len(chunks)))

    status.empty()
    return "\n\n".join([r for r in all_reports if r.strip()]), total_metrics, raw_chunks


# =========================
# UI
# =========================
with st.sidebar:
    st.subheader("Entrada")
    input_mode = st.radio("Modo de entrada", ["Archivos XML", "Texto XML"], index=0)

    st.subheader("Modelo")
    model_name = st.selectbox(
        "Modelo",
        [
            "gemini-2.5-flash",
            "gemini-2.5-pro",
            "gemini-2.0-flash",
        ],
        index=0,
    )
    temperature = st.slider("Temperature", 0.0, 0.5, 0.0, 0.05)

    st.subheader("Alcance")
    scope = st.selectbox("Focus", ["balanced", "waf", "cdn"], index=0)

    st.subheader("Chunking")
    chunk_size = st.number_input("Chunk size (chars)", min_value=50_000, max_value=500_000, value=180_000, step=10_000)
    chunk_overlap = st.number_input("Chunk overlap (chars)", min_value=0, max_value=80_000, value=12_000, step=1_000)

    st.subheader("Riesgo / Robustez")
    safety_off = st.checkbox("Desactivar safety (menos bloqueos)", value=True)
    normalize = st.checkbox("Normalizar whitespace", value=True)

    st.caption("Notas: chunk_size/overlap en caracteres. Valores enormes degradan memoria/latencia en Streamlit Cloud.")

tab_exec, tab_tech = st.tabs(["Executive", "Técnico"])

xml_text: str = ""

with tab_exec:
    st.subheader("Carga")
    if input_mode == "Archivos XML":
        files = st.file_uploader("Subir archivos XML", type="xml", accept_multiple_files=True)
        if files:
            texts = []
            for f in files:
                texts.append(_read_uploaded_file_as_text(f))
            xml_text = "\n\n".join(texts)
    else:
        xml_text = st.text_area("Pegar XML aquí", height=260, placeholder="<policy>...</policy>")

    if xml_text:
        if normalize:
            xml_text = _normalize_whitespace(xml_text)

        c_run, c_dl = st.columns([1, 1])
        with c_run:
            run = st.button("Iniciar auditoría", type="primary", use_container_width=True)

        if run:
            try:
                with st.spinner("Procesando..."):
                    report, metrics, raw_chunks = run_audit_chunked(
                        content=xml_text,
                        model_name=model_name,
                        temperature=temperature,
                        safety_off=safety_off,
                        mode=scope,
                        chunk_size=int(chunk_size),
                        chunk_overlap=int(chunk_overlap),
                    )

                # KPIs
                k1, k2, k3, k4 = st.columns(4)
                k1.metric("Crítico", metrics["Critico"])
                k2.metric("Alto", metrics["Alto"])
                k3.metric("Medio", metrics["Medio"])
                k4.metric("Bajo", metrics["Bajo"])

                # Chart
                df = pd.DataFrame({"Nivel": list(metrics.keys()), "Fallas": list(metrics.values())})
                fig = px.bar(df, x="Nivel", y="Fallas", color="Nivel")
                st.plotly_chart(fig, use_container_width=True)

                # Report
                st.subheader("Hallazgos")
                st.markdown(report if report.strip() else "- Sin hallazgos detectables con el fragmento provisto.")

                # Persist for technical tab + downloads
                st.session_state["last_report_md"] = report
                st.session_state["last_metrics"] = metrics
                st.session_state["last_raw_chunks"] = raw_chunks
                st.session_state["last_model"] = model_name
                st.session_state["last_scope"] = scope

                with c_dl:
                    export = {
                        "model": model_name,
                        "scope": scope,
                        "metrics": metrics,
                        "chunks": raw_chunks,
                    }
                    st.download_button(
                        "Descargar JSON (debug)",
                        data=json.dumps(export, ensure_ascii=False, indent=2).encode("utf-8"),
                        file_name="audit_output.json",
                        mime="application/json",
                        use_container_width=True,
                    )

            except Exception as e:
                st.error(f"Error: {e}")


with tab_tech:
    st.subheader("Detalle técnico / Debug")
    if "last_raw_chunks" not in st.session_state:
        st.info("Ejecuta una auditoría para ver el detalle.")
    else:
        st.write(
            {
                "model": st.session_state.get("last_model"),
                "scope": st.session_state.get("last_scope"),
                "metrics": st.session_state.get("last_metrics"),
                "chunks": len(st.session_state.get("last_raw_chunks", [])),
            }
        )

        raw_chunks = st.session_state["last_raw_chunks"]
        idx = st.number_input("Ver chunk", min_value=0, max_value=max(0, len(raw_chunks) - 1), value=0, step=1)

        st.markdown("#### Métricas del chunk")
        st.json(raw_chunks[int(idx)].get("metrics", {}))

        st.markdown("#### Reporte del chunk")
        st.code(raw_chunks[int(idx)].get("report", ""), language="markdown")

        st.download_button(
            "Descargar reporte Markdown",
            data=(st.session_state.get("last_report_md", "") or "").encode("utf-8"),
            file_name="audit_report.md",
            mime="text/markdown",
        )
