"""Converts informe_final.md to a professional academic PDF using markdown-it-py and PyMuPDF."""

import os
import re
from pathlib import Path
import fitz
import markdown_it

PROJECT_ROOT = Path(__file__).parent.parent.resolve()
MD_PATH = PROJECT_ROOT / "informe_final.md"
PDF_PATH = PROJECT_ROOT / "informe_final.pdf"
TMP_PDF_PATH = PROJECT_ROOT / "informe_final_tmp.pdf"


def clean_markdown_for_html(md_text: str) -> str:
    """Preprocess markdown to format mermaid and alert boxes cleanly."""
    # Convert Mermaid diagram to a styled ASCII architecture box
    mermaid_pattern = re.compile(r"```mermaid\n(.*?)```", re.DOTALL)
    
    ascii_diagram = """```text
========================================================================================
                          FLUJO DE CONTROL Y AUTORIZACION DE LA POC
========================================================================================

  [ Issue no confiable: fixtures/issue_*.txt ]
                      │
                      ▼
  [ Agente de Desarrollo: DeterministicAgent / OllamaAgent ]
                      │
                      ▼
  [ Acción propuesta en formato JSON estructurado ]
  {"tool": "write_file", "params": {"path": "...", "content": "..."}}
                      │
        ┌─────────────┴─────────────────────────────────┐
        │                                               │
        ▼ (Perfil Vulnerable)                           ▼ (Perfil Mitigado)
  [ Ejecución Directa ]                   [ Controlador: SecurityController ]
  - Omite autorización de negocio         - Valida herramienta en lista blanca
  - Mantiene contención en sandbox        - Verifica esquema estricto de parámetros
        │                                 - Prohíbe modificación de recursos protegidos
        │                                 - Valida confinamiento de ruta (Anti-Traversal)
        │                                               │
        │                                ┌──────────────┴──────────────┐
        │                                │ DENEGADA                    │ AUTORIZADA
        ▼                                ▼                             ▼
  [ lab_workspace/secret.txt ]    [ AuditLogger ]              [ lab_workspace/public.txt ]
  (RECURSO COMPROMETIDO)          (Evento registrado en JSONL) (ESCRITURA EXITOSA)
========================================================================================
```"""
    
    md_text = mermaid_pattern.sub(ascii_diagram, md_text)
    
    # Format GitHub style alert callouts
    md_text = re.sub(r"> \[!(NOTE|TIP|IMPORTANT|WARNING|CAUTION)\]\s*", r"**[\1]** ", md_text)
    
    return md_text


def build_pdf() -> int:
    print(f"[+] Leyendo archivo Markdown desde: {MD_PATH}")
    raw_md = MD_PATH.read_text(encoding="utf-8")
    processed_md = clean_markdown_for_html(raw_md)

    print("[+] Renderizando Markdown a HTML...")
    md = markdown_it.MarkdownIt().enable("table")
    html_body = md.render(processed_md)

    css = """
    @page {
        size: A4;
        margin: 45pt;
    }
    body {
        font-family: sans-serif;
        font-size: 9.5pt;
        line-height: 1.45;
        color: #2d3748;
    }
    h1 {
        color: #1a365d;
        font-size: 16pt;
        border-bottom: 2px solid #3182ce;
        padding-bottom: 4px;
        margin-top: 18pt;
        margin-bottom: 8pt;
    }
    h2 {
        color: #2b6cb0;
        font-size: 13pt;
        border-bottom: 1px solid #e2e8f0;
        padding-bottom: 3px;
        margin-top: 14pt;
        margin-bottom: 6pt;
    }
    h3 {
        color: #2d3748;
        font-size: 10.5pt;
        margin-top: 10pt;
        margin-bottom: 4pt;
    }
    p {
        margin-top: 4pt;
        margin-bottom: 6pt;
        text-align: justify;
    }
    table {
        width: 100%;
        border-collapse: collapse;
        margin: 10pt 0;
        font-size: 8.5pt;
    }
    th, td {
        border: 1px solid #cbd5e0;
        padding: 5pt 7pt;
        text-align: left;
    }
    th {
        background-color: #ebf8ff;
        color: #1a365d;
        font-weight: bold;
    }
    tr:nth-child(even) td {
        background-color: #f7fafc;
    }
    pre, code {
        font-family: monospace;
        font-size: 8pt;
        background-color: #f7fafc;
    }
    code {
        padding: 1pt 3pt;
        border-radius: 2pt;
        border: 1px solid #edf2f7;
    }
    pre {
        border: 1px solid #e2e8f0;
        padding: 7pt;
        border-radius: 3pt;
        margin: 6pt 0;
        white-space: pre-wrap;
        word-break: break-all;
    }
    blockquote {
        border-left: 3px solid #3182ce;
        background-color: #ebf8ff;
        padding: 5pt 10pt;
        margin: 6pt 0;
        font-style: italic;
    }
    ul, ol {
        margin-top: 3pt;
        margin-bottom: 6pt;
        padding-left: 18pt;
    }
    li {
        margin-bottom: 2pt;
    }
    hr {
        border: 0;
        border-top: 1px solid #e2e8f0;
        margin: 12pt 0;
    }
    """

    full_html = f"""<!DOCTYPE html>
    <html>
    <head>
        <meta charset="utf-8">
        <style>{css}</style>
    </head>
    <body>
        {html_body}
    </body>
    </html>
    """

    print("[+] Creando documento PDF con PyMuPDF (fitz.Story)...")
    if TMP_PDF_PATH.exists():
        TMP_PDF_PATH.unlink()

    writer = fitz.DocumentWriter(str(TMP_PDF_PATH))
    story = fitz.Story(html=full_html)

    # A4 dimensions: 595.28 x 841.89 points
    # Printable area: margins 45pt left/right, 45pt top/bottom
    def get_rect(rect_num, filled):
        mediabox = fitz.Rect(0, 0, 595, 842)
        content_rect = fitz.Rect(45, 45, 595 - 45, 842 - 50)
        return mediabox, content_rect, None

    story.write(writer, get_rect)
    writer.close()
    del writer
    import gc
    gc.collect()

    print("[+] Agregando encabezados, pies de página y numeración...")
    doc = fitz.open(str(TMP_PDF_PATH))
    total_pages = len(doc)

    for i in range(total_pages):
        page = doc[i]
        # Running header on subsequent pages
        if i > 0:
            page.insert_text(
                fitz.Point(45, 30),
                "agent-injection-lab | Informe Final de Investigación y Seguridad en IA",
                fontsize=7.5,
                color=(0.35, 0.35, 0.35),
            )
            page.draw_line(
                fitz.Point(45, 34),
                fitz.Point(550, 34),
                color=(0.8, 0.8, 0.8),
                width=0.5,
            )

        # Running footer on all pages
        page.insert_text(
            fitz.Point(45, 822),
            "Trabajo Práctico Académico - Seguridad en IA (2026)",
            fontsize=7.5,
            color=(0.35, 0.35, 0.35),
        )
        footer_page_text = f"Página {i + 1} de {total_pages}"
        page.insert_text(
            fitz.Point(495, 822),
            footer_page_text,
            fontsize=7.5,
            color=(0.35, 0.35, 0.35),
        )
        page.draw_line(
            fitz.Point(45, 814),
            fitz.Point(550, 814),
            color=(0.8, 0.8, 0.8),
            width=0.5,
        )

    if PDF_PATH.exists():
        try:
            PDF_PATH.unlink()
        except Exception:
            pass

    doc.save(str(PDF_PATH))
    doc.close()
    del doc
    import gc
    gc.collect()

    # Remove temporary PDF safely
    if TMP_PDF_PATH.exists():
        try:
            TMP_PDF_PATH.unlink()
        except Exception:
            pass

    print(f"[+] PDF generado exitosamente en: {PDF_PATH}")
    print(f"[+] Total de páginas: {total_pages}")
    return 0


if __name__ == "__main__":
    exit(build_pdf())
