FROM nginx:alpine

# 1. On remplace la configuration par défaut de Nginx par la vôtre
COPY default.conf /etc/nginx/conf.d/default.conf

# 2. On copie uniquement les fichiers web dans le dossier public
COPY index.html /usr/share/nginx/html/

EXPOSE 80