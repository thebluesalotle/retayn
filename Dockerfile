FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    RETAYN_DATA_DIR=/data

WORKDIR /app
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt
COPY . ./

EXPOSE 8787
CMD ["sh", "-c", "uvicorn retayn_app:app --host 0.0.0.0 --port ${PORT:-8787} --workers 1"]
