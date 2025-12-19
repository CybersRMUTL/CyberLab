FROM php:7-apache
EXPOSE 6009
COPY ./ /var/www/html
RUN mkdir /var/www/html/uploads && \
    chown -R www-data:www-data /var/www/html/ && \
    chmod -R 777 /var/www/html/uploads
RUN echo "ServerName localhost" >> /etc/apache2/apache2.conf
CMD ["/usr/sbin/apache2ctl", "-D", "FOREGROUND"]
