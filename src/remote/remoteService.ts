import fetch from "node-fetch";
import {AppLogger, Logger} from "../logger/logger";
import {SignatureResponse} from "../auth/signatureResponse";

export interface RemoteService {
    keys(principal: string): Promise<string>;
    signPayload(principal: string, remoteName: string, fingerprint: string, text: string, buttonText: string,
                                encodedPayload: string, flags: number): Promise<SignatureResponse>;
    getSignUrl(encodedPayload: string): string;

    hostname(): string;

    port(): number;
}

export class RemoteServiceImpl implements RemoteService {

    private readonly _hostname: string;
    private readonly _port: number;
    private readonly _logger: Logger;

    constructor(hostname: string, port = 443, logger: Logger = new AppLogger()) {
        this._hostname = hostname;
        this._port = port;
        this._logger = logger;
    }

    hostname(): string {
        return this._hostname;
    }

    port(): number {
        return this._port;
    }

    get logger(): Logger {
        return this._logger;
    }

    public async keys(principal: string) {

        const response = await fetch(`https://${this.hostname()}:${this.port()}/authorizedKeys/${principal}`);
        return await response.text();
    }

    public async signPayload(principal: string, remoteName: string, fingerprint: string, text: string, buttonText: string,
                encodedPayload: string, flags: number): Promise<SignatureResponse> {

        const params = new URLSearchParams();
        params.append('username', principal);
        params.append('fingerprint', fingerprint);
        params.append('remoteName', remoteName);
        params.append('text', text);
        params.append('authorizeText', buttonText);
        params.append('flags', String(flags));
        params.append('payload', encodedPayload);

        const responseJson = await fetch(`https://${this.hostname()}:${this.port()}/app/api/authenticator/signPayload`,
            {method: 'POST', body: params});
        return await responseJson.json() as SignatureResponse;

    }

    public getSignUrl(encodedPayload: string) {
        let port = 443;
        if (this.port() != 443) {
            port = this.port();
        }

        return `https://${this.hostname()}:${port}/authenticator/sign/${encodedPayload}`;
    }
}