import {VcIssuer} from "@sphereon/oid4vci-issuer";
import {AuthorizationRequest} from "@sphereon/oid4vci-common";
import {randomBytes} from "node:crypto";

export const authorizeController = async (req, res) => {
    const issuer = req.app.locals.issuer as VcIssuer<object>;
    const authReq = req.query as unknown as AuthorizationRequest;
    console.log('auth req', JSON.stringify(authReq, null, 2));

    // invalid_request rfc7636
    if(!authReq["code_challenge"] &&
        !authReq["code_challenge_method"] &&
        authReq["code_challenge_method"] !== "S256"){
        res.status(400).json({error: "invalid_request"});
        return;
    }

    /*
        This is out of scope of specs OID4VCI, OID Connect and OAuth 2.0
        Implementation using hardcoded username and password and
        use of HTTP Basic is chosen because of simplicity.
 */
    const b64auth = (req.headers.authorization || '').split(' ')[1] || ''
    const [login, password] = Buffer.from(b64auth, 'base64').toString().split(':')
    if(login != 'user' || password != 'user'){
        res.setHeader('WWW-Authenticate', 'Basic realm="Issuer"')
            .sendStatus(401);
        return;
    }

    const data = {manufacturer:"Blue Inc."};

    const codeLengthInBytes = !!parseInt(process.env.CODE_LENGTH) ? parseInt(process.env.CODE_LENGTH) : 16;
    const code: string = randomBytes(codeLengthInBytes).toString("hex");

    let offerSession = await issuer.credentialOfferSessions.get(authReq.issuer_state);
    await issuer.credentialOfferSessions.delete(authReq.issuer_state);
    await issuer.credentialOfferSessions.set(code, {...offerSession,
        credentialDataSupplierInput: data,
        // @ts-ignore
        code_challange: authReq.code_challenge,
        code_challenge_method:authReq.code_challenge_method,
        code
    });

    console.log(`redirect with code ${code}`)
    res.redirect(`${authReq.redirect_uri}/?code=${code}`);
}