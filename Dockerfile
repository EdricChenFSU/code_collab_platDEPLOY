FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV PORT=3000
ENV DATA_DIR=/data

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN mkdir -p /data && \
	addgroup --system appgroup && \
	adduser --system --ingroup appgroup appuser && \
	chown -R appuser:appgroup /app /data
	
USER appuser

EXPOSE 3000

CMD gunicorn -b 0.0.0.0:${PORT} --workers 1 --threads 25 --timeout 120 app:app
