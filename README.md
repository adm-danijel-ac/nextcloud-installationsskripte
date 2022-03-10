# nextcloud-installationsskripte
Installieren Sie Ihren eigenen Nextcloud-Server in weniger als 15 Minuten.

* Debian 11+
* Ubuntu 20.04+

Sofern Sie das Skript erneut ausführen möchten, so führen Sie bitte zuerst folgende Befehle aus:

sudo apt remove --purge -y nginx* php* mariadb-* galera-* redis* fail2ban ufw --allow-change-held-packages
sudo rm -Rf /etc/ufw /etc/fail2ban

Dabei werden alle Softwarepakete sowie Verzeichnisse und Daten aus vorherigen Installationen entfernt.
Im Anschluss daran kann die Installation erneut durchgeführt werden.
 
Weitere Optimierungs-, Härtungs- und Erweiterungsmöglichkeiten werden unter
https://www.c-rieger.de/nextcloud-installationsanleitung/
beschrieben. Viel Spaß.

Carsten Rieger IT-Services
