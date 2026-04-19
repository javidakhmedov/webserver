FROM nginx:alpine

# 1. Sistemdəki libpng və zlib boşluqlarını (CVE-ləri) bağlayırıq
RUN apk update && apk upgrade && \
    apk add --no-cache libpng zlib

# 2. Bütün frontend fayllarını kopyalayırıq
COPY . /usr/share/nginx/html/

# 3. Nginx konfiqurasiyasını təhlükəsizlik header-ləri ilə yazırıq
RUN echo 'server { \
    listen 80; \
    location / { \
        root /usr/share/nginx/html; \
        index index.html; \
        try_files $uri $uri/ /index.html; \
    } \
    add_header X-Frame-Options "DENY"; \
    add_header X-Content-Type-Options "nosniff"; \
    add_header X-XSS-Protection "1; mode=block"; \
}' > /etc/nginx/conf.d/default.conf

EXPOSE 80
