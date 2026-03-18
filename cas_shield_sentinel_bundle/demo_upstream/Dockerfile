FROM python:3.11-slim

WORKDIR /app

RUN pip install --no-cache-dir fastapi==0.115.0 uvicorn==0.30.6

COPY demo_cas.py /app/demo_cas.py

EXPOSE 9090
CMD ["uvicorn", "demo_cas:app", "--host", "0.0.0.0", "--port", "9090"]
