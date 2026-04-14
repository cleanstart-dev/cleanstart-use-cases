FROM cleanstart/node:latest-dev AS builder
WORKDIR /app
COPY package*.json ./
RUN npm install
COPY src/ ./src/
COPY tsconfig.json .
RUN npm run build

FROM cleanstart/node:latest AS runtime
WORKDIR /app
COPY --from=builder /app/dist ./dist
COPY --from=builder /app/package*.json .
RUN npm install --omit=dev
EXPOSE 3000
CMD ["dist/index.js"]