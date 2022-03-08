# LogonBox Authenticator API for NodeJS

Use this API to integrate LogonBox Authenticator into your own NodeJS application authentication flows.  

The LogonBox Authenticator uses an authentication mechanism similar to SSH private key authentication where users keys are published in an authorized keys listing on the credential server. This API will read the trusted public keys and then submit an authentication request payload to the credential server for signing by the corresponding private key. 

As part of the signing operation, the user must authorize the request within the LogonBox Authenticator app. Once authorized the payload is signed by the private key, which is held exclusively within the secure storage of the app. 

To authenticate the user, the API verifies the signature returned to obtain the authentication result.

# About LogonBox Authenticator

Safeguard your people, passwords and apps with [LogonBox's](https://logonbox.com) 2-Factor [Authentication app](https://www.logonbox.com/content/logonbox-authenticator/) for Android and iOS. 

![LogonBox Logo](https://github.com/nervepoint/logonbox-brand/blob/main/LogonBox-Logo-250x50.png?raw=true)


## Other Languages

 * [Python](https://github.com/nervepoint/logonbox-authenticator-python)
 * [Java](https://github.com/nervepoint/logonbox-authenticator-java)
 * [PHP](https://github.com/nervepoint/logonbox-authenticator-php)

## Usage

**Direct Signing**

If you are using a different protocol and cannot redirect the user via a web browser, or want to provide your own user interface, you can perform authentication exclusively through the API.


```typescript
import {AuthenticatorClient} from "./auth/authenticatorClient";
import {RemoteServiceImpl} from "./remote/remoteService";

async function main() {
    const remoteService = new RemoteServiceImpl("some.directory.org");
    const authenticatorClient = new AuthenticatorClient(remoteService);
    authenticatorClient.debug = true;
    const signatureResponse = await authenticatorClient.authenticate("myuser@directory.com");
    const verify = signatureResponse.verify();
    console.log("The success is", verify);


}
main().then(() => console.log("Done."));
```


**Server Redirect**

If you are logging a user into a web application, you can create a request, and redirect the user to a URL on the credential server where they are prompted to authorize the request on their device. This eliminates the need for you to create your own user interface and provides a modern, clean authentication flow.

When authentication completes, the server redirects back to your web application with an authentication response which you pass into the API for verification.


```typescript
import * as http from "http";
import * as url from "url";
import * as querystring from "querystring";
import {IncomingMessage, ServerResponse} from "http";
import {RemoteServiceImpl} from "./remote/remoteService";
import {AuthenticatorClient} from "./auth/authenticatorClient";
import {AuthenticatorRequest} from "./auth/authenticatorRequest";

const host = 'localhost';
const port = 9090;

const remoteService = new RemoteServiceImpl("some.directory.org");
const authenticatorClient = new AuthenticatorClient(remoteService);
authenticatorClient.debug = true;

const sessionMap = new Map<string, string>();
const cookieKey = "token";

const requestListener = async function (req: IncomingMessage, res: ServerResponse) {

    if (req.url === "/login" && req.method === "GET") {
        res.setHeader("Content-Type", "text/html");
        res.writeHead(200);
        res.end(loginHTML);
    } else if (req.url === "/login" && req.method === "POST") {

        let body = "";

        req.on("data", function (data) {
            body += data;

            // Too much POST data, kill the connection!
            // 1e6 === 1 * Math.pow(10, 6) === 1 * 1000000 ~~~ 1MB
            if (body.length > 1e6)
                req.socket.destroy();
        });

        req.on("end", async function () {
            const post = querystring.parse(body);
            const user = post["user"] as string;

            if (user) {
                const authenticatorRequest = await authenticatorClient.generateRequest(user,
                    "http://localhost:9090/authenticator-finish?response={response}");

                // !!!!!!!!!!!!!! PLEASE TAKE NOTE !!!!!!!!!!!!!!!!
                // please use strong cookie/session management api
                // this is for demonstration purpose only
                const cookie = `${cookieKey}=value; HttpOnly`;
                sessionMap.set("value", authenticatorRequest.encodedPayload);

                res.writeHead(302, {
                    'Location': authenticatorRequest.getSignUrl(),
                    'Set-Cookie': cookie,
                });
                res.end();
                return;
            }

            res.writeHead(400);
            res.end("Bad request!");
        });



    } else if (req.url.startsWith("/authenticator-finish") && req.method === "GET") {
        const cookie = req.headers.cookie || '';
        if (cookie) {
            const token = cookie.split(";")
                .filter((val: string) => val.trim().split("=")[0] === cookieKey)
                .map((val: string) => val.trim().split("=")[1])
                .pop();
            const payload = sessionMap.get(token);

            if (payload) {
                const queryData = url.parse(req.url, true).query;
                if (queryData && queryData.response) {
                    try {
                        const authenticatorRequest = new AuthenticatorRequest(authenticatorClient, payload);
                        const response = queryData.response;
                        const authenticatorResponse = await authenticatorRequest.processResponse(response as string);
                        res.writeHead(200);
                        res.end(`Done => ${authenticatorResponse.verify()}`);

                    } catch (e) {
                        res.writeHead(403);
                        res.end(`Done => ${e}`);
                    }

                    return;
                }
            }
        }

        res.writeHead(400);
        res.end("Bad request!");
    } else {
        res.writeHead(404);
        res.end("Page not found!");
    }
};

const server = http.createServer(requestListener);
server.listen(port, host, () => {
    console.log(`Server is running on http://${host}:${port}`);
});


const loginHTML = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Login</title>
</head>
<body>
<form method="post" action="/login">
  <input type="text" name="user" value="" />
  <button type="submit" name="submit">Submit</button>
</form>
</body>
</html>`;
```

## Debugging

A simple Logger interface is used that will output to `console.log` and `console.error` by default. You can enable this after you have created the client object.

```typescript
authenticatorClient.debug = true;
```

This should be sufficient for testing. To integrate logging into your wider application just provide an implementation of `Logger` to the `constructor` of `AuthenticatorClient`.

```typescript
import {AuthenticatorClient} from "./authenticatorClient";

const remoteService = new RemoteServiceImpl("some.directory.org");
const myLogger = new MyApplicationLogger();

const authenticatorClient = new AuthenticatorClient(remoteService, myLogger);
```

## Minimum Requirements

Current stable release requires at least Node.js 12.20.0.
