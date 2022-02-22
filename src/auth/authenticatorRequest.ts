import {AuthenticatorClient} from "./authenticatorClient";

export class AuthenticatorRequest {
    private readonly _authenticatorClient: AuthenticatorClient;
    private readonly _encodedPayload: string;


    constructor(authenticatorClient: AuthenticatorClient, encodedPayload: string) {
        this._authenticatorClient = authenticatorClient;
        this._encodedPayload = encodedPayload;
    }

    get authenticatorClient(): AuthenticatorClient {
        return this._authenticatorClient;
    }

    get encodedPayload(): string {
        return this._encodedPayload;
    }

    public processResponse(response: string) {
        const payload =  Buffer.from(this.encodedPayload, "base64url");
        const signature =  Buffer.from(response, "base64url");

        return this.authenticatorClient.processResponse(payload, signature);
    }
}