FROM python:3.11-slim

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy all source files (matching your exact filenames)
COPY server.py .
COPY sars.py .
COPY storage.py .
COPY evaluator.py .
COPY llm_client.py .
COPY cvss4_0.py .
COPY prompts_cvss4_0.py .
COPY prompts_clawhub.py .
COPY clawhub/clawhub_fetch.py .
COPY templates.html .
COPY metrics.json .

# Copy reports and skills directories
COPY data/ ./data/
COPY reports/ ./reports/
COPY skills/ ./skills/
COPY eval/ ./eval/
COPY clawhub/ ./clawhub/

# Ensure reports dir is writable (HF runs as non-root)
RUN mkdir -p reports && chmod -R 777 reports

EXPOSE 7860

CMD ["python", "server.py", \
     "--port", "7860", \
     "--reports-dir", "reports", \
     "--skills-dir", "remote"]
     