FROM python:3.11-alpine



ENV PYTHONDONTWRITEBYTECODE 1

ENV PYTHONUNBUFFERED 1



WORKDIR /app

FROM python:3.11-alpine

ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1

WORKDIR /app

# 1. Sistem paketləri
RUN apk update && apk upgrade && \
    apk add --no-cache \
    gcc \
    musl-dev \
    postgresql-dev \
    libffi-dev

# 2. Python paketləri
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip setuptools && \
    pip install --no-cache-dir -r requirements.txt

# 3. Proqram kodu
COPY . .

# 4. İstifadəçi tənzimləmələri
RUN adduser -D appuser && chown -R appuser /app
USER appuser

EXPOSE 8000

# ƏN VACİB DƏYİŞİKLİK BURADADIR:
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000", "--proxy-headers", "--forwarded-allow-ips", "*"]
