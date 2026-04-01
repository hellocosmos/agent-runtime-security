"""유틸리티 함수"""
from __future__ import annotations


def extract_text_from_pdf(path: str) -> str:
  """PDF 파일에서 텍스트를 추출한다.
  pymupdf가 설치되어 있어야 한다: pip install agent-runtime-security[pdf]
  """
  try:
    import pymupdf
  except ImportError:
    raise ImportError(
        "PDF 텍스트 추출에는 pymupdf가 필요합니다. "
        "pip install agent-runtime-security[pdf] 로 설치하세요."
    )
  doc = pymupdf.open(path)
  text_parts = []
  for page in doc:
    text_parts.append(page.get_text())
  doc.close()
  return "\n".join(text_parts)
