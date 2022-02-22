import SshPK = require("sshpk");
import {AlgorithmHashType} from 'sshpk'

export class AuthenticatorResponse {
    private readonly _payload: Buffer;
    private readonly _signature: Buffer;
    private readonly _publicKey: SshPK.Key;
    private readonly _flags: number;

    constructor(payload: Buffer, signature: Buffer, publicKey: SshPK.Key, flags: number) {
        this._payload = payload;
        this._signature = signature;
        this._publicKey = publicKey;
        this._flags = flags;
    }

    get payload(): Buffer {
        return this._payload;
    }

    get signature(): Buffer {
        return this._signature;
    }

    get publicKey(): SshPK.Key {
        return this._publicKey;
    }

    get flags(): number {
        return this._flags;
    }

    public verify(): boolean {

        if (this.signature === undefined) {
            return false;
        }

        switch (this.publicKey.type) {
            case "rsa": {
                return this.verifyRSASignature()
            }

            case "ed25519": {
                return this.verifyEd25519Signature();
            }

            case "ecdsa": {
                return this.verifyEcDSASignature();
            }

            default: throw new Error(`Unsupported algorithm ${this.publicKey.type}`);
        }
    }

    private verifyRSASignature() {
        const signature = SshPK.parseSignature(this.signature, "rsa", "asn1");
        let hashAlgo: AlgorithmHashType;
        switch (this.flags) {
            case 4: {
                hashAlgo = "sha512";
                break;
            }

            case 2: {
                hashAlgo = "sha256";
                break;
            }

            default: {
                hashAlgo = "sha1";
            }
        }

        return this.verifySignature(signature, hashAlgo);
    }

    private verifyEd25519Signature() {
        const signature = SshPK.parseSignature(this.signature, "ed25519", "asn1");
        return this.verifySignature(signature, "sha512");
    }

    private verifyEcDSASignature() {
        const signature = SshPK.parseSignature(this.signature, "ecdsa", "ssh");
        return this.verifySignature(signature, "sha512");
    }

    private verifySignature(signature: SshPK.Signature, hashAlgo: AlgorithmHashType) {
        const verifier = this.publicKey.createVerify(hashAlgo);
        verifier.update(this.payload);
        return verifier.verify(signature);
    }
}