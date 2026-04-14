FROM cleanstart/node:latest-dev
WORKDIR /app
COPY package*.json ./
RUN npm install
COPY src/ ./src/
COPY tsconfig.json .
RUN npm run build
EXPOSE 3000
CMD ["dist/index.js"]