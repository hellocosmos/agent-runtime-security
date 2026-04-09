FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /workspace

# Build from the repository root:
# docker build -f deploy/api/Dockerfile -t agent-runtime-security-api .
COPY . /workspace

RUN pip install --no-cache-dir -e ".[api,dev]"

EXPOSE 8000

CMD ["uvicorn", "asr.api.main:app", "--host", "0.0.0.0", "--port", "8000"]
