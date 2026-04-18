FROM node:20

ARG INTERNAL_API_ORIGIN=http://127.0.0.1:8000
ENV INTERNAL_API_ORIGIN=${INTERNAL_API_ORIGIN}

WORKDIR /app
COPY package*.json ./
RUN npm install
COPY . .
RUN npm run build

CMD ["npm", "start"]
