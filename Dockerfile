FROM node:18.18.0-alpine3.18
WORKDIR /app
COPY ["package.json", "package-lock.json", "./"]
RUN npm ci
COPY . /app

CMD ["npx", "ts-node", "."]
