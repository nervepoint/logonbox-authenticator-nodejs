import * as SshPK from "sshpk";
import * as crypto from "crypto";
import {Logger, AppLogger} from "../logger/logger";
import {AuthenticatorResponse} from "./authenticatorResponse";
import {AuthenticatorRequest} from "./authenticatorRequest";
import {RemoteService} from "../remote/remoteService";
// eslint-disable-next-line @typescript-eslint/no-var-requires
const SSHBuffer = require('sshpk/lib/ssh-buffer');

export class AuthenticatorClient {

    private readonly _logger: Logger;
    private readonly _remoteService: RemoteService

    private _remoteName = "LogonBox Authenticator API";
    private _promptText = "{principal} wants to authenticate from {remoteName} using your {hostname} credentials.";
    private _authorizeText = "Authorize";

    constructor(remoteService: RemoteService, logger: Logger = new AppLogger()) {
        this._logger = logger;
        this._remoteService = remoteService;
    }

    get remoteService() {
        return this._remoteService;
    }

    get remoteName() {
        return this._remoteName;
    }

    set remoteName(value: string) {
        this._remoteName = value;
    }

    get promptText() {
        return this._promptText;
    }

    set promptText(value: string) {
        this._promptText = value;
    }

    get authorizeText() {
        return this._authorizeText;
    }

    set authorizeText(value: string) {
        this._authorizeText = value;
    }

    get logger() {
        return this._logger;
    }

    set debug(debug: boolean) {
        this.logger.enableDebug(debug)
    }

    public async getUserKeys(principal: string): Promise<SshPK.Key[]> {

        try {
            const body = await this.remoteService.keys(principal);

            if (this.logger.isDebug()) {
                this.logger.info(body);
            }

            const keys = body.split(/\r\n?|\n/);

            if (this.logger.isDebug()) {
                this.logger.info(keys.join(","));
            }

            return keys.filter(key => !key.trim().startsWith("#"))
                .map(key => {

                    if (this.logger.isDebug()) {
                        this.logger.info(`Parsing key ${key}.`);
                    }

                    const sshKey = SshPK.parseKey(key, 'auto');

                    if (this.logger.isDebug()) {
                        this.logger.info(`Decoded ${sshKey.type} public key.`);
                    }

                    return sshKey;
                })
        } catch (e) {
            this.logger.error("Problem in fetching keys.", e);
        }
    }

    public async authenticate(principal: string) {
        const payload = crypto.randomBytes(128);
        return await this.authenticateWithPayload(principal, payload);
    }

    public async authenticateWithPayload(principal: string, payload: Buffer) {
        const keys = await this.getUserKeys(principal);
        for (let i = 0; i < keys.length; ++i) {
            try {
                const key = keys[i];
                return await this.signPayload(principal, key, this.replaceVariables(this.promptText, principal), this.authorizeText, payload);
            } catch (e) {
                this.logger.error(e);
            }
        }

        return  new AuthenticatorResponse(payload, undefined, undefined, 0);
    }

    public async processResponse(payload: Buffer, signature: Buffer) {
        const sigBuff = new SSHBuffer({buffer: signature});
        const success = sigBuff.readChar();

        if (success === "1") {
            const username = sigBuff.readString();
            const fingerprint = sigBuff.readString();
            const flags = sigBuff.readInt();
            const signatureBuff = sigBuff.readBuffer();

            return new AuthenticatorResponse(payload, signatureBuff, (await this.getUserKey(username, fingerprint)), flags);
        } else {
            throw new Error(sigBuff.readString());
        }
    }

    public async generateRequest(principal: string, redirectURL: string) {
        const request = new SSHBuffer();

        const publicKey = await this.getDefaultKey(principal);
        const fingerprint = publicKey.fingerprint().toString();
        const flags = this.getFlags(publicKey);
        const noise = crypto.randomBytes(16);
        const nonce = crypto.randomBytes(4);

        request.writeString(principal);
        request.writeString(fingerprint);
        request.writeString(this.remoteName);
        request.writeString(this.promptText);
        request.writeString(this.authorizeText);
        request.writeInt(flags);
        request.writeInt(nonce);
        request.writeString(redirectURL);
        request.write(noise);

        const encoded = request.toBuffer().toString("base64url");

        return new AuthenticatorRequest(this, encoded);
    }

    public async getUserKey(principal: string, fingerprint: string) {
        const key = (await this.getUserKeys(principal)).find(key => key.fingerprint().toString() === fingerprint);

        if (key == null || typeof key === 'undefined') {
            throw new Error(`No suitable key found for fingerprint ${fingerprint}`);
        }

        return key;
    }

    public async getDefaultKey(principal: string) {
        const keys = await this.getUserKeys(principal);

        let defaultKey = keys.find(key => key.type !== "rsa");

        if (defaultKey == null || typeof defaultKey === 'undefined') {
            defaultKey = keys.find(key => key.type === "rsa");
        }

        return defaultKey;
    }

    public getFlags(publicKey: SshPK.Key) {
        if (publicKey.type === "rsa") {
            return 4;
        }

        return 0;
    }

    private async signPayload(principal: string, key: SshPK.Key, text: string, buttonText: string, payload: Buffer) {
        const fingerprint = key.fingerprint().toString();

        if (this.logger.isDebug()) {
            this.logger.info(`Key fingerprint is ${fingerprint}`);
        }

        const encodedPayload = payload.toString("base64url");
        let flags = 0;
        if (key.type === "rsa") {
            // Tell the server we want a RSAWithSHA512 signature
            flags = 4;
        }

        const signature = await this.requestSignature(principal, fingerprint, text, buttonText, encodedPayload, flags);
        return new AuthenticatorResponse(payload, signature, key, flags);
    }

    private async requestSignature(principal: string, fingerprint: string, text: string, buttonText: string,
                             encodedPayload: string, flags: number) {

        const body = await this.remoteService.signPayload(principal, this.remoteName, fingerprint, text, buttonText, encodedPayload, flags);

        if (this.logger.isDebug()) {
            this.logger.info(JSON.stringify(body));
        }

        const { success, signature, message, response } = body;

        if (!success) {
            throw new Error(message);
        }

        if (signature.trim() === '') {
            const data = Buffer.from(response, "base64url");

            const dataBuff = new SSHBuffer({buffer: data});
            const success = dataBuff.readChar();

            if (success !== "1") {
                throw new Error(dataBuff.readString());
            }
            throw new Error("The server did not respond with a valid response!");
        }

        return Buffer.from(body.signature, "base64url");
    }

    private replaceVariables(promptText: string, principal: string) {
        return promptText.replace("{principal}", principal)
            .replace("{remoteName}", this.remoteName)
            .replace("{hostname}", this.remoteService.hostname());
    }
}