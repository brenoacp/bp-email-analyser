# Stage 1: Build do Frontend com Node
FROM node:20-alpine AS builder

WORKDIR /app

COPY frontend/package.json ./
RUN npm install

COPY frontend/ ./
RUN npm run build

# Stage 2: Runtime Nginx
FROM nginx:1.27-alpine AS runtime

# Remove configuração padrão
RUN rm /etc/nginx/conf.d/default.conf

# Copia arquivo principal de configuração
COPY docker/nginx/nginx.conf /etc/nginx/nginx.conf

# Copia o template que utilizará envsubst para substituir ${DOMAIN}
COPY docker/nginx/templates/default.conf.template /etc/nginx/templates/default.conf.template

# Copia os arquivos compilados da SPA
COPY --from=builder /app/dist /usr/share/nginx/html

# Cria diretório para desafio do Certbot
RUN mkdir -p /var/www/certbot

EXPOSE 80 443

CMD ["nginx", "-g", "daemon off;"]
