## pixelserv-tls
_pixelserv-tls_ is a fork of pixelserv with added support for HTTPS - the tiny webserver that responds to all requests with "nothing" and yet particularly useful for whitelisting hosts for troubled websites, and for mining "big data" on adservers and trackers.

Certificates for adserver domains are automatically generated at real-time upon first request. All requests to adserver are optionally written to syslogd. The stats in text format are preserved, good for command line parsing. The same stats in HTML format are revamped to be more legible.

### Prepare your Root CA cert

_pixelserv-tls_ requires a Root CA cert to run. Use Easy-RSA 3.0 to generate this cert on PC or routers. Easy-RSA 3.0 requires `mktemp` and OpenSSL which are available in most Linux distributions and router firmwares with Entware-ng. Follow this [EasyRSA Quickstart] guide. Only the first two steps are needed:
* `./easyrsa init-pki`
* `./easyrsa build-ca nopass`

When prompted for a Common Name, type in "Pixelserv CA".

When EasyRSA finishes, it places `ca.crt` and `ca.key` under `pki` and `pki/private` sub-dirs respectively. Upload these two files to `/opt/var/cache/pixelserv` on your router.

### Import ca.crt into Clients

Note that installation of `ca.cert` on client OS is not mandatory but recommended. Clients without `ca.crt` will interact smoothly with pixelserv-tls.

#### MacOS

In Terminal, type
* `sudo security add-trusted-cert -d -r trustRoot -k /System/Library/Keychains/SystemRootCertificates.keychain ca.crt`

Note: since OS X El Capitan, System Integrity Protection need to be disabled first. Reboot, then run the above command line. System Integrity Protection can be enabled afterward. Here is a [SIP tutorial] to disable/enable System Integrity Protection. `ca.crt` need to be re-added after every OS update unfortunately.

#### iOS

Multiple ways to get it done. The simplest is to email yourself `ca.crt`. Go to your iOS device. Click on the attachment and follow the instructions.

Here is a [guide by IBM] that provides a bit more details.

#### Windows

Chrome/IE/Edge uses Root CA certs from Windows system-wide repository. Follow this [Windows guide] carefully to add ca.cert into the system-wide Root CAs.

Firefox manages its own repository of Root CAs. Follow this [Firefox guide] only if you also run Firefox.

#### Android

This [Android guide] looks interesting. I don't have Android devices. Please provide feedback after you tried.

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

|Mnemonics|Explanation
|---------|-----------
|uts|uptime in seconds
|req|number of connection requests
|avg|average request size in bytes
|rmx|maximum request size in bytes
|tav|average request processing time in milliseconds
|tmx|maximum request processing time in milliseconds
|err|number of connections resulting in processing errors (syslog may have details)
|tmo|number of connections that timed out while trying to read a request from the client
|cls|number of connections that were closed by the client while reading or replying to the request
|nou|number of requests that failed to include a URL
|pth|number of requests for a path that could not be parsed
|nfe|number of requests for a file with no extension
|ufe|number of requests for an unrecognized/unhandled file extension
|gif|number of requests for GIF images
|bad|number of requests for unrecognized/unhandled HTTP methods
|txt|number of requests for plaintext data formats
|jpg|number of requests for JPEG images
|png|number of requests for PNG images
|swf|number of requests for Adobe Shockwave Flash files
|ico|number of requests for ICO files (usually favicons)
|slh|number of HTTPS requests with a good certifcate (cert exists and used) 
|slm|number of HTTPS requests without a certficate (cert missing for ad domain)
|sle|number of HTTPS requests with a bad cert (error in existing cert)
|slu|number of unrecognized HTTPS requests (none of slh/slm/sle)
|sta|number of requests for HTML stats
|stt|number of requests for plaintext stats
|204|number of requests for /generate_204 URLs
|rdr|number of requests resulting in a redirect
|pst|number of requests for HTTP POST method
|hed|number of requests for HTTP HEAD method
|log|status of access loggging

### Forum Threads
* [pixelserv-tls]: Pixelserv with support for HTTPS born here.
* [pixelserv]: The thread on LinksysInfo.org where the parent of this fork is produced.
* [pixelserv-ddwrt]: An even older thread of an early version of pixelserv.
 
[EasyRSA Quickstart]: <https://github.com/OpenVPN/easy-rsa/blob/v3.0.0-rc1/README.quickstart.md>
[Windows guide]: <https://support.comodo.com/index.php?/Default/Knowledgebase/Article/View/636/17/>
[Firefox guide]: <https://wiki.wmtransfer.com/projects/webmoney/wiki/Installing_root_certificate_in_Mozilla_Firefox>
[SIP tutorial]: <http://osxdaily.com/2015/10/05/disable-rootless-system-integrity-protection-mac-os-x/>
[guide by IBM]: <https://www.ibm.com/support/knowledgecenter/#!/SSHSCD_7.0.0/com.ibm.worklight.installconfig.doc/admin/t_installing_root_CA_iOS.html>
[Android guide]: <http://wiki.pcprobleemloos.nl/android/cacert>
[pixelserv-tls]: <http://www.snbforums.com/threads/pixelserv-a-better-one-pixel-webserver-for-adblock.26114>
[pixelserv]: <http://www.linksysinfo.org/index.php?threads/pixelserv-compiled-to-run-on-router-wrt54g.30509/page-3#post-229342>
[pixelserv-ddwrt]: <http://www.dd-wrt.com/phpBB2/viewtopic.php?p=685201>
