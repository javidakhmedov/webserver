FROM postgres:15-alpine

# 1. Sistem paketlərini (zlib daxil) ən son təhlükəsiz versiyaya qaldırırıq
# Bu, hesabatındakı o HIGH və MEDIUM zlib xətalarını tamamilə siləcək
RUN apk update && apk upgrade && \
    apk add --no-cache zlib libcrypto3 libssl3

# Postgres-in rəsmi ayarlarını qoruyuruq
