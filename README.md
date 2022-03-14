# nextcloud-installationsskripte
Installieren Sie Ihren eigenen Nextcloud-Server in weniger als 15 Minuten.

* Debian 11+
* Ubuntu 20.04+

<b>INSTALLATION:</b>

<code>sudo -s</code><br>
<code>mkdir /nextcloud-installation && cd /nextcloud-installation</code><br>
<code>git clone https://github.com/criegerde/nextcloud-installationsskripte.git</code><br>
<code>cp nextcloud-installationsskripte/<b><i>ubuntu</i></b>-install.sh /nextcloud-installation/</code><br>
oder<br>
<code>cp nextcloud-installationsskripte/<b><i>debian</i></b>-install.sh /nextcloud-installation/</code><br>
<code>./install.sh</code><br>

Sofern Sie das Skript erneut ausführen möchten, so führen Sie bitte zuerst die Deinstallation aus:

<code>/nextcloud-installation/uninstall.sh</code><br>

Dabei werden alle Softwarepakete sowie Verzeichnisse und Daten aus vorherigen Installationen entfernt.
Im Anschluss daran kann die Installation erneut durchgeführt werden.
 
<code>sudo -s</code><br>
<code>/nextcloud-installation/install.sh</code><br>

Weitere Optimierungs-, Härtungs- und Erweiterungsmöglichkeiten werden unter
https://www.c-rieger.de/nextcloud-installationsanleitung/
beschrieben. Viel Spaß.

Carsten Rieger IT-Services
