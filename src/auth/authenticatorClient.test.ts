import {RemoteService} from "../remote/remoteService";
import {SignatureResponse} from "./signatureResponse";
import * as SshPK from "sshpk";
import {AuthenticatorClient} from "./authenticatorClient";

const sshPrivateKey = SshPK.generatePrivateKey("ed25519");
sshPrivateKey.comment = "Testing key !!!!";

const sshPublicKey = sshPrivateKey.toPublic();

const sshPublicKeyFormat = (principal: string) => {
    return `# Testing keys for principal ${principal} .........
            ${sshPublicKey.toString("ssh")}`;
}

const MockedRemoteService = jest.fn(() => ({
    hostname(): string {
        return "some.directory.org";
    },

    port(): number {
        return 443;
    },

    async keys(principal: string): Promise<string> {
        return sshPublicKeyFormat(principal);
    },

    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    getSignUrl(encodedPayload: string): string {
        return "";
    },

    async signPayload(principal: string, remoteName: string, fingerprint: string, text: string,
                      // eslint-disable-next-line @typescript-eslint/no-unused-vars
                      buttonText: string, encodedPayload: string, flags: number): Promise<SignatureResponse> {
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        const signer = sshPrivateKey.createSign("sha512" as any);
        signer.update(Buffer.from(encodedPayload, "base64url"));
        const signature = signer.sign();

        return {
            success: true,
            signature: signature.toBuffer("asn1").toString("base64url")
        } as SignatureResponse;
    }

} as RemoteService));

describe("authenticator client tests", () => {

    beforeEach(() => {
        // Clear all instances and calls to constructor and all methods:
        MockedRemoteService.mockClear();
    });

    it('should fetch list of ssh keys',  async () => {
        const ac = new AuthenticatorClient(MockedRemoteService());
        ac.debug = true;

        const keys = await ac.getUserKeys("TestUser");

        expect(keys.length).toBe(1);
        expect(keys[0].fingerprint().toString()).toBe(sshPublicKey.fingerprint().toString());
    });

    it("should sign payload", async () => {
       const ac = new AuthenticatorClient(MockedRemoteService());
       ac.debug = true;

       const response = await ac.authenticate("TestUser");
       const verify = response.verify();

       expect(verify).toBeTruthy();
    });

    it("should throw error if remote response does not return signature", async () => {
        const MockedFailedRemoteService = jest.fn(() => ({
            hostname(): string {
                return "some.directory.org";
            },

            port(): number {
                return 443;
            },
            async keys(principal: string): Promise<string> {
                return sshPublicKeyFormat(principal);
            },
            // eslint-disable-next-line @typescript-eslint/no-unused-vars
            async signPayload(principal: string, remoteName: string, fingerprint: string,
                              // eslint-disable-next-line @typescript-eslint/no-unused-vars
                        text: string, buttonText: string, encodedPayload: string, flags: number): Promise<SignatureResponse> {

                return {
                    success: false,
                } as SignatureResponse;
            }
        } as RemoteService));


        const ac = new AuthenticatorClient(MockedFailedRemoteService());
        ac.debug = true;

        const response = await ac.authenticate("TestUser");
        const verify = response.verify();

        expect(verify).toBeFalsy();
    });
});