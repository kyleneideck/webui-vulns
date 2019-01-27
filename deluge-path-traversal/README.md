# Path Traversal in the web UI of Deluge 1.3.13

[CVE-2017-9031](https://nvd.nist.gov/vuln/detail/CVE-2017-9031), reported March 2017

Deluge is a BitTorrent client available from <https://deluge-torrent.org>.

## Fix

Fixed in [Deluge
1.3.15](https://dev.deluge-torrent.org/wiki/ReleaseNotes/1.3.15). See
<https://git.deluge-torrent.org/deluge/commit/?h=develop&id=960f3a6552a47549ef46dee5f9579ccf317d7bbf>
and
<https://git.deluge-torrent.org/deluge/commit/?h=1.3-stable&id=41acade01ae88f7b7bbdba308a0886771aa582fd>.
Thanks to Calum Lind (Cas) of Deluge Team for getting the issue resolved so
quickly.

## Details

The `/render` endpoint of the Web UI plug-in of Deluge 1.3.13 allows files
outside of the Deluge installation to be read via crafted URLs. The Web UI
plug-in is installed, but not enabled, by default.

If the user has enabled the Web UI plug-in and the web UI is publicly
accessible, an attacker can request files directly by including `/`,
percent-encoded as `%2f`, in the filepath that follows `/render/` in the URL.
For example,
<http://host:8112/render/%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd>.
(8112 is the default port for the web UI.)

The relevant code in
[`server.py`](https://git.deluge-torrent.org/deluge/tree/deluge/ui/web/server.py?h=develop&id=35c78eee41426bd21a0b689fda75b48fda593a57#n128):

```Python
class Render(resource.Resource):
    [...]
    def render(self, request):
        [...]
        filename = os.path.join('render', request.render_file)
        template = Template(filename=rpath(filename))
        request.setHeader(b'content-type', b'text/html')
        request.setResponseCode(http.OK)
        return compress(template.render(), request)
```

This likely allows remote code execution in most cases, as the web UI password
hash (SHA1) and salt can be read from the `web.conf` file in the Deluge user
configuration directory (e.g.  `~/.config/deluge/web.conf`). If an attacker can
reverse the hash and recover the password, they should then be able to log in to
the web UI and install a malicious Deluge plug-in. The plug-in could then run
arbitrary code as the user running Deluge.

