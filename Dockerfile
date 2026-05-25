FROM openresty/openresty:1.27.1.2-0-alpine-fat

COPY build/docker/site-lualib /usr/local/openresty/site/lualib
COPY build/docker/log-placeholder /var/log/sparrow/gateway/.keep
COPY nginx.conf /usr/local/openresty/nginx/conf/nginx.conf
COPY lua /usr/local/openresty/nginx/lua

EXPOSE 8088 1883

CMD ["openresty", "-g", "daemon off;"]
