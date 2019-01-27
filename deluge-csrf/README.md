# Remote code execution via CSRF in the web UI of Deluge 1.3.13

February 2017

[CVE-2017-7178](https://nvd.nist.gov/vuln/detail/CVE-2017-7178)

## Product

Deluge is a BitTorrent client available from <https://deluge-torrent.org>.

## Fix

Fixed in
<https://git.deluge-torrent.org/deluge/commit/?h=develop&id=11e8957deaf0c76fdfbac62d99c8b6c61cfdddf9>
and
<https://git.deluge-torrent.org/deluge/commit/?h=1.3-stable&id=318ab179865e0707d7945edc3a13a464a108d583>.

## Summary

Deluge version 1.3.13 is vulnerable to cross-site request forgery in the Web UI
plug-in resulting in remote code execution. Requests made to the `/json`
endpoint are not checked for CSRF. See the `render` function of the class `JSON`
in
[`deluge/ui/web/json_api.py`](https://git.deluge-torrent.org/deluge/tree/deluge/ui/web/json_api.py?h=develop&id=ec5c8bafb660ddf8109f8584943ec0316427f45f#n221).

The Web UI plug-in is installed, but not enabled, by default. If the user has
enabled the Web UI plug-in and logged into it, a malicious web page can use
forged requests to make Deluge download and install a Deluge plug-in provided by
the attacker. The plug-in can then execute arbitrary code as the user running
Deluge (usually the local user account).

## Timeline

- 2017-03-01 Disclosed the vulnerability to Calum Lind (Cas) of Deluge Team
- 2017-03-01 Vulnerability fixed by Calum Lind
- 2017-03-05 Advisory released

## To Reproduce

- Create/find a Deluge plug-in to be installed on the victim machine. For
  example, create an empty plug-in with
  ```
  python deluge/scripts/create_plugin.py --name malicious --basepath . \
      --author-name "n" --author-email "e"
  ```
  (see
  <https://git.deluge-torrent.org/deluge/tree/deluge/scripts/create_plugin.py?h=1.3-stable&id=318ab179865e0707d7945edc3a13a464a108d583>)
  and add a line to its `__init__.py` to launch `calc.exe`.
- Build the plug-in as a .egg (if necessary):
  ```
  python malicious/setup.py bdist_egg
  ```
- Make a torrent containing the .egg and seed it somewhere.
- Create a Magnet link for the torrent.
- In the proof-of-concept page linked below, update the `PLUGIN_NAME`,
  `PLUGIN_FILE` and `MAGNET_LINK` constants.
- Put the PoC on a web server somewhere. Serving it locally is fine.
- In Deluge, open Preferences, go to the Plugins category and enable the Web
  UI plug-in.
- Go to the WebUi preferences section and check "Enable web interface". The
  port should be set to 8112 by default.
- If you're serving the PoC over HTTPS, check "Enable SSL" so its requests
  don't get blocked as mixed content. If you're not, SSL can be either enabled
  or disabled.
- Go to `localhost:8112` in a browser on the victim machine and log in.
- Open the PoC in the same browser.

The PoC sends requests to `localhost:8112` that include cookies. The first
request adds the torrent, which downloads the .egg (the plug-in) to `/tmp`. It
then sends repeated requests to install the .egg and enable it. The attacker's
code in the plug-in runs when the plug-in is enabled.

For the attack to be successful, the PoC page must be left open until the
malicious plug-in finishes downloading. An attacker could avoid that limitation
by using the Execute plug-in, which is installed by default, but Deluge has to
be restarted before the Execute plug-in can be used. I don't think that can be
done from the web UI, so the attacker's code would only execute after the victim
restarted Deluge and then added/removed/completed a torrent.

The PoC adds the plug-in torrent using a Magnet link because it would need to
read the web UI's responses to add a .torrent file, which CORS prevents.

## Proof of Concept

See [proof-of-concept.html](proof-of-concept.html).

