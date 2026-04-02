"""Utility helpers."""
from __future__ import annotations


def extract_text_from_pdf(path: str) -> str:
  """Extract text from a PDF file.

  Requires ``pymupdf``:
    pip install agent-runtime-security[pdf]
  """
  try:
    import pymupdf
  except ImportError:
    raise ImportError(
        "pymupdf is required for PDF text extraction. "
        "Install it with: pip install agent-runtime-security[pdf]"
    )
  doc = pymupdf.open(path)
  text_parts = []
  for page in doc:
    text_parts.append(page.get_text())
  doc.close()
  return "\n".join(text_parts)
