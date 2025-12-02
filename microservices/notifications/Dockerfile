FROM node:20-alpine

WORKDIR /app

COPY package*.json ./
RUN npm ci --only=production

COPY . .

ENV NODE_ENV=production
ENV NOTIFI_PORT=4002
EXPOSE 4002

CMD ["node", "index.js"]
