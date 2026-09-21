FROM nginx:alpine

# 1. On remplace la configuration de Nginx
COPY default.conf /etc/nginx/conf.d/default.conf

# 2. On copie TOUT le contenu du dossier "public" (fichiers, sous-dossiers, images...)
COPY public/ /usr/share/nginx/html/

EXPOSE 80