# Node 24 LTS; digest фіксує образ, оновлюється свідомо разом із CI.
FROM node:24-alpine@sha256:ebfe2f90462722a7a4de65e91990e97fe0d401c70e0e762c5b53302f905ec1c1

WORKDIR /app
ENV NODE_ENV=production
COPY --chown=node:node --chmod=0644 package.json package-lock.json ./
# git потрібен npm: частина залежностей jkurwa тягнеться з git-URL
RUN apk add --no-cache git \
	&& npm ci --omit=dev \
	&& npm cache clean --force \
	&& apk del git

COPY --chown=node:node --chmod=0644 signer.js server.js ./

USER node
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
	CMD node -e "require('http').get('http://127.0.0.1:8080/health',r=>process.exit(r.statusCode===200?0:1)).on('error',()=>process.exit(1))"
CMD ["node", "server.js"]
