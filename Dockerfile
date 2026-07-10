FROM node:20-alpine

WORKDIR /app
COPY package.json ./
# git потрібен npm: частина залежностей jkurwa тягнеться з git-URL
RUN apk add --no-cache git \
    && npm install --omit=dev \
    && npm cache clean --force \
    && apk del git

COPY signer.js server.js ./

USER node
EXPOSE 8080
CMD ["node", "server.js"]
