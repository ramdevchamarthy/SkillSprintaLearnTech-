# SkillSprinta LearnTech prototype server: the app, the API, OCR (tesseract + poppler).
FROM node:22-bookworm-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends tesseract-ocr tesseract-ocr-eng poppler-utils ca-certificates \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY server.js ./
COPY public ./public
ENV NODE_ENV=production \
    PORT=8787 \
    DB_PATH=/data/skillsprinta.sqlite \
    SECURE_COOKIES=1 \
    TRUST_PROXY=1
RUN mkdir -p /data && chown node:node /data
USER node
VOLUME ["/data"]
EXPOSE 8787
CMD ["node", "server.js"]
