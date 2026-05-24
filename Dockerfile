FROM python:3.11-slim

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy all source files matching the new directory structure
COPY source_code/ ./source_code/
COPY clawhub/ ./clawhub/
COPY __init__.py .

# Copy data, skills, and evaluation results
COPY metrics.json .
COPY data/ ./data/
COPY reports/ ./reports/
COPY skills/ ./skills/
COPY eval/ ./eval/

# Ensure reports dir is writable (HF runs as non-root)
RUN mkdir -p reports && chmod -R 777 reports

EXPOSE 7860

CMD ["python", "source_code/Backend/server.py", \
     "--port", "7860", \
     "--reports-dir", "reports", \
     "--skills-dir", "remote"]
