## pixelserv-tls
_pixelserv-tls_ is a fork of pixelserv with added support for HTTPS - the tiny webserver that responds to all requests with "nothing" and yet particularly useful for whitelisting hosts on troubled websites, and for mining "big data" on adservers and trackers.

Certificates for adserver domains are automatically generated at real-time upon first request. All requests to adserver are optionally written to syslogd. The stats in text format are preserved, good for command line parsing. The same stats in HTML format are revamped to be more legible.

### Prepare your Root CA cert

_pixelserv-tls_ requires a Root CA cert to run. Assume OpenSSL already installed in your systems. Execute the following statements in a command shell:

* `cd /opt/var/cache/pixelserv`
* `openssl genrsa -out ca.key 1024`
* `openssl req -key ca.key -new -x509 -days 3650 -sha256 -extensions v3_ca -out ca.crt -subj "/CN=Pixelserv CA"`

These create a 1024-bit CA cert with Common Name "Pixelserv CA" in `/opt/var/cache/pixelserv`.

### Import ca.crt into Clients

Note that installation of `ca.cert` on client OS is not mandatory but recommended. Clients without `ca.crt` will interact smoothly with pixelserv-tls.

#### iOS

Multiple ways to get it done. The simplest is to email yourself `ca.crt`. Go to your iOS device. Click on the attachment and follow the instructions.

Here is a [guide by IBM] that provides a bit more details.

#### Android

Email yourself the CA cert as attachment. Double click on the attachment and follow on-screen instructions to import the certificate. I found this way the CA cert will be imported in "User" category instead of "System" category. That's no problem as the CA cert is still properly recognized. If people insist on importing into "System" certificates, try this [Android guide].

#### MacOS

In Terminal, type
* `sudo security add-trusted-cert -d -r trustRoot -k /System/Library/Keychains/SystemRootCertificates.keychain ca.crt`

Note: since OS X El Capitan, System Integrity Protection need to be disabled first. Reboot, then run the above command line. System Integrity Protection can be enabled afterward. Here is a [SIP tutorial] to disable/enable System Integrity Protection. `ca.crt` need to be re-added after every OS update unfortunately.

#### Windows

Chrome/IE/Edge uses Root CA certs from Windows system-wide repository. Follow this [Windows guide] carefully to add ca.cert into the system-wide Root CAs.

Firefox manages its own repository of Root CAs. Follow this [Firefox guide] only if you also run Firefox.

### Launch pixelserv-tls
A few examples of launching _pixelserv-tls_:
* `pixelserv-tls 192.168.1.1`
* `pixelserv-tls 192.168.1.1 -p 80 -p 8080 -k 443 -k 2443 -u admin`

The first example runs pixelserv as `nobody` with non-root privilege. Listens on port 80 for HTTP and 443 for HTTPS. The second example additionally listens on 8080 for HTTP and 2443 for HTTPS, and runs as `admin` - the root account in ASUSWRT.

### Binaries

pixelserv-tls is now (circa April 2016) available on Entware-NG. Use `opkg install pixelserv-tls` to install on supported platforms including Asuswrt/Merlin.

Going forward binaries for Asuswrt/Merlin in Releases section will be provided only on requests.

### New command line switches
```
$ pixelserv-tls --help
Usage:pixelserv-tls
	ip_addr/hostname (all if omitted)
	-2 (disable HTTP 204 reply to generate_204 URLs)
	-f (stay in foreground - don't daemonize)
	-k https_port (443 if omitted)
	-l (log access to syslog)
	-n i/f (all interfaces if omitted)
	-o select_timeout (10 seconds)
	-p http_port (80 if omitted)
	-r (deprecated - ignored)
	-R (disable redirect to encoded path in tracker links)
	-s /relative_stats_html_URL (/servstats if omitted)
	-t /relative_stats_txt_URL (/servstats.txt if omitted)
	-u user ("nobody" if omitted)
	-z path_to_https_certs (/opt/var/cache/pixelserv if omitted)
```
`-k`, `-l` and `-z` are new options. `-k` specifies one https port and use multiple times for more ports.

`-l` will log all ad requests to syslogd. If we don't specify in the command line, no logging which is the default. Access logging can generate lots of data. Either use it only when troubleshoot a browsing issue or you have a more capable syslog on your router (e.g. syslog-ng + logrotate from Entware).

`-z` specifies the path to certs storage. Each ad domain and its sub-domain will require one wildcard cert. Generated certs will be stored and re-used from there.

### Stats

Stats are viewable by default at http://pixelservip/servstats.txt (for raw text format) or http://pixelservip/servstats for html format), where pixelserv ip is the ip address that pixelserv is listening on.

<table><tbody>
<tr><td><b>Mnemonics</b></td><td><b>Example</b></td><td><b>Explanation</b></td></tr><tr><th colspan="3"></th></tr>
<tr><td>uts</td><td>2d 17:50</td><td>pixelserv uptime</td></tr><tr><td>log</td><td>1</td><td>logging access to syslog (0=disabled 1=enabled)</td></tr><tr><th colspan="3"></th></tr><tr><td>req</td><td>18122</td><td>total # of requests (HTTP, HTTPS, success, failure etc)</td></tr><tr><td>avg</td><td>514 bytes</td><td>average length of request URL</td></tr><tr><td>rmx</td><td>25965 bytes</td><td>maximum length of request URL</td></tr><tr><td>tav</td><td>12 ms</td><td>average processing time (per request)</td></tr><tr><td>tmx</td><td>17036 ms</td><td>maximum processing time (per request)</td></tr><tr><th colspan="3"></th></tr><tr><td>slh</td><td>8824</td><td># of accepted HTTPS requests</td></tr><tr><td>slm</td><td>5</td><td># of rejected HTTPS requests (missing certificate)</td></tr><tr><td>sle</td><td>0</td><td># of rejected HTTPS requests (certificate available but bad)</td></tr><tr><td>slu</td><td>14</td><td># of dropped HTTPS requests (unknown error)</td></tr><tr><th colspan="3"></th></tr><tr><td>nfe</td><td>3830</td><td># of GET requests for server-side scripting</td></tr><tr><td>gif</td><td>165</td><td># of GET requests for GIF</td></tr><tr><td>ico</td><td>0</td><td># of GET requests for ICO</td></tr><tr><td>txt</td><td>7895</td><td># of GET requests for Javascripts</td></tr><tr><td>jpg</td><td>9</td><td># of GET requests for JPG</td></tr><tr><td>png</td><td>6</td><td># of GET requests for PNG</td></tr><tr><td>swf</td><td>0</td><td># of GET requests for SWF</td></tr><tr><td>sta</td><td>7</td><td># of GET requests for HTML stats</td></tr><tr><td>stt</td><td>0</td><td># of GET requests for plain text stats</td></tr><tr><td>ufe</td><td>956</td><td># of GET requests /w unknown file extension</td></tr><tr><th colspan="3"></th></tr><tr><td>rdr</td><td>799</td><td># of GET requests resulted in REDIRECT response</td></tr><tr><td>nou</td><td>1</td><td># of GET requests /w empty URL</td></tr><tr><td>pth</td><td>0</td><td># of GET requests /w malformed URL</td></tr><tr><td>204</td><td>0</td><td># of GET requests (HTTP 204 response)</td></tr><tr><td>pst</td><td>588</td><td># of POST requests (HTTP 501 response)</td></tr><tr><td>hed</td><td>7</td><td># of HEAD requests (HTTP 501 response)</td></tr><tr><td>bad</td><td>1</td><td># of unknown HTTP requests (HTTP 501 response)</td></tr><tr><th colspan="3"></th></tr><tr><td>err</td><td>0</td><td># of dropped requests (failed to accept client connection)</td></tr><tr><td>tmo</td><td>1030</td><td># of dropped requests (client timeout before connection accepted)</td></tr><tr><td>cls</td><td>2828</td><td># of dropped requests (client disconnect before connection accepted)</td></tr></tbody></table>

### Forum Discussion for pixelserv-tls
[pixelserv-tls]: Tentative page on kazoo.ga for announcement and support of pixelserv-tls.

### Other References
* [pixelserv-tls on snb]: The previous support thread for Pixelserv-tls.
* [pixelserv]: The thread on LinksysInfo.org where the parent of this fork is produced.
* [pixelserv-ddwrt]: An even older thread of an early version of pixelserv.
* [Page load time]: Measure page load time in Google Chrome

[Page load time]: <http://kazoo.ga/measure-page-load-time-in-google-chrome/>
[Windows guide]: <https://support.comodo.com/index.php?/Default/Knowledgebase/Article/View/636/17/>
[Firefox guide]: <https://wiki.wmtransfer.com/projects/webmoney/wiki/Installing_root_certificate_in_Mozilla_Firefox>
[SIP tutorial]: <http://osxdaily.com/2015/10/05/disable-rootless-system-integrity-protection-mac-os-x/>
[guide by IBM]: <https://www.ibm.com/support/knowledgecenter/#!/SSHSCD_7.0.0/com.ibm.worklight.installconfig.doc/admin/t_installing_root_CA_iOS.html>
[Android guide]: <http://wiki.pcprobleemloos.nl/android/cacert>
[pixelserv-tls]: <https://kazoo.ga/pixelserv-tls/>
[pixelserv-tls on snb]: <http://www.snbforums.com/threads/pixelserv-a-better-one-pixel-webserver-for-adblock.26114>
[pixelserv]: <http://www.linksysinfo.org/index.php?threads/pixelserv-compiled-to-run-on-router-wrt54g.30509/page-3#post-229342>
[pixelserv-ddwrt]: <http://www.dd-wrt.com/phpBB2/viewtopic.php?p=685201>
