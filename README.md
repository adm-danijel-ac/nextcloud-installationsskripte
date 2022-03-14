# nextcloud-installationsskripte
Installieren Sie Ihren eigenen Nextcloud-Server in weniger als 15 Minuten.

* Debian 11+
* Ubuntu 20.04+

<h2>INSTALLATION:</h2>

<h3>Vorbereitung:</h3>
<code>sudo -s</code><br>
<code>mkdir /nextcloud-installation && cd /nextcloud-installation</code><br>
<code>git clone https://github.com/criegerde/nextcloud-installationsskripte.git</code><br>

<h3>Skriptauswahl:</h3>
<code>cp nextcloud-installationsskripte/<b><i>ubuntu</i></b>-install.sh /nextcloud-installation/install.sh</code><br>
oder<br>
<code>cp nextcloud-installationsskripte/<b><i>debian</i></b>-install.sh /nextcloud-installation/install.sh</code><br>

<h3>install.sh:</h3>
<code>/nextcloud-installation/install.sh</code><br>


<h2>DEINSTALLATION:</h2>
Sofern Sie das Skript erneut ausführen möchten, so führen Sie bitte zuerst die Deinstallation aus:
<h3>uninstall.sh:</h3>
<code>/nextcloud-installation/uninstall.sh</code><br>

Dabei werden alle Softwarepakete sowie Verzeichnisse und Daten aus vorherigen Installationen entfernt.
Im Anschluss daran kann die Installation erneut durchgeführt werden.
 
<code>sudo -s</code><br>
<code>/nextcloud-installation/install.sh</code><br>

Weitere Optimierungs-, Härtungs- und Erweiterungsmöglichkeiten werden unter
https://www.c-rieger.de/nextcloud-installationsanleitung/
beschrieben. Viel Spaß.

Carsten Rieger IT-Services
