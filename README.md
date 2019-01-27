# Local Web UI Vulnerabilities

In 2016 and 2017 I spent a bit of time looking for security bugs in the apps I
use that have web UIs. That is, the application includes a web server and the
user controls the app through their browser.

There are a lot of good reasons to provide a web UI, and I think they tend to be
more pleasant to write, but they're usually harder to secure than native UIs
are.

Some of these vulnerabilities are a little interesting, but I think the more
interesting thing was that I found vulnerabilities in three of the four apps I
investigated. (The fourth was [SABNZBd](https://sabnzbd.org/).)

Also, all of the vulnerabilities I found could be used to remotely execute
arbitrary code on the user's system under some conditions. Though that might
have more to do with the type of applications I looked into, since they happened
to be somewhat related.

Most of the vulnerabilities share similarities as well. They mostly allow some
form of [CSRF](https://en.wikipedia.org/wiki/Cross-site_request_forgery) that
can change the app's configuration.

I didn't look for bugs in any of the [Electron](https://electronjs.org/) apps I
use, but apparently they can also suffer from some of the kinds of
vulnerabilities commonly found in web apps. See [Modern Alchemy: Turning XSS
into RCE](https://blog.doyensec.com/2017/08/03/electron-framework-security.html)
and [CVE-2018-1000136 - Electron nodeIntegration
Bypass](https://www.trustwave.com/en-us/resources/blogs/spiderlabs-blog/cve-2018-1000136-electron-nodeintegration-bypass/).

I should also mention that all of the developers I reported these
vulnerabilities to were very responsive and got fixes out to their users
quickly.

## Deluge

[A CSRF bug](deluge-csrf/) (CVE-2017-7178) and [a path traversal
bug](deluge-path-traversal/) (CVE-2017-9031) in the
[Deluge](https://deluge-torrent.org) BitTorrent client, version 1.3.13.

## Sonarr

[A CSRF bug and an authentication bypass bug](sonarr/) in version 2.0.0.5054 of
[Sonarr](https://sonarr.tv/), a PVR application.

## Plex Media Server

[A CSRF bug](plex/plex-media-server-csrf.html) in [Plex Media
Server](https://www.plex.tv/downloads/) v1.0.3, a personal media library
application. First discovered by [Stefan Viehböck of SEC Consult Vulnerability
Lab](https://sec-consult.com/fxdata/seccons/prod/temedia/advisories_txt/20140411-0_Plex_Media_Server_Multiple_Vulnerabilities_v10.txt)
in v0.9.9.10.

