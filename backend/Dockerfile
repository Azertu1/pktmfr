# Utilise l'image officielle Node.js allégée
FROM node:22-alpine

# Définit le dossier de travail à l'intérieur du conteneur
WORKDIR /app

# Copie d'abord les fichiers de définition des paquets
# (Cela permet à Docker de mettre le téléchargement en cache si package.json n'a pas changé)
COPY package*.json ./

# Installe les dépendances définies dans package.json (Express, etc.)
RUN npm install

# Copie tout le reste de votre code source backend
COPY . .

# Indique le port sur lequel votre serveur Node.js écoute en interne
EXPOSE 3000

# Commande exécutée au démarrage du conteneur
CMD ["node", "index.js"]