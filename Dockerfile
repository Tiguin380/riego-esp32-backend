FROM node:18-alpine

WORKDIR /app

# Necesario en Alpine para disponer de la base de datos de zonas horarias (IANA)
# usada por Intl.DateTimeFormat("Europe/Madrid").
RUN apk add --no-cache tzdata

ENV TZ=UTC

COPY package*.json ./

RUN npm ci --only=production

COPY . .

EXPOSE 3000

CMD ["npm", "start"]
