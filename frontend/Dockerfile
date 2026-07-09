FROM node:18-alpine

WORKDIR /app

COPY package*.json ./
RUN npm install

COPY . .

# Compile l'application pour générer le dossier dist
RUN npm run build

EXPOSE 5173
CMD ["npm", "run", "dev", "--", "--host"]