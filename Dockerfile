FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app
RUN adduser --disabled-password --gecos "" appuser
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
RUN mkdir -p instance uploads reports logs && chown -R appuser:appuser /app
USER appuser
EXPOSE 8000
CMD ["gunicorn", "-c", "gunicorn.conf.py", "wsgi:application"]
