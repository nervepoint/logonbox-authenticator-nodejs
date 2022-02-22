import {AuthenticatorClient} from "./auth/authenticatorClient";
import {RemoteServiceImpl} from "./remote/remoteService";

async function main() {
    const remoteService = new RemoteServiceImpl("corp.logonbox.directory");
    const authenticatorClient = new AuthenticatorClient(remoteService);
    authenticatorClient.debug = true;
    const signatureResponse = await authenticatorClient.authenticate("gaurav.bagga@protonmail.com");
    const verify = signatureResponse.verify();
    console.log("The success is", verify);


}
main().then(r => console.log("Done.")); // eslint-disable-line @typescript-eslint/no-unused-vars
