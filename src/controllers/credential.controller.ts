import {VcIssuer} from "@sphereon/oid4vci-issuer";
import {importJWK, jwtVerify, KeyLike} from "jose";
import {UniResolver} from "@sphereon/did-uni-client";
import {CredentialRequestV1_0_11} from "@sphereon/oid4vci-common";
import {credentialDataSupplier} from "../service/issuer";

/*
    Checks if credential has required fields
 */
function validateCredentialReq(credentialReq: CredentialRequestV1_0_11) {
    const requiredProperties = ['type', 'format', 'proof'];
    const keys = Object.keys(credentialReq);
    if (!requiredProperties.every(prop => keys.includes(prop))) {
        return false;
    }
    if (keys.length !== requiredProperties.length) {
        return false;
    }
    return true;
}

export const credentialController = async (req, res) => {
    const issuer = req.app.locals.issuer as VcIssuer<object>;

    // resolve issuer public key
    let publicKey: Uint8Array | KeyLike;
    try{
        const resolver = new UniResolver();
        const didResolutionResult = await resolver.resolve(process.env.PUBLIC_KEY_DID);
        const {publicKeyJwk} = didResolutionResult.didDocument.verificationMethod[0];
        publicKey = await importJWK(publicKeyJwk);
    } catch (e) {
        console.error(e);
        res.setHeader('Cache-Control', 'no-store').status(500)
            .json({error: "server_error"})
    }

    // check if token is valid
    const authorisationHeader = req.headers["authorization"];
    if(!authorisationHeader && !req.headers["authorization"].startsWith("Bearer")){
        /*
           https://datatracker.ietf.org/doc/html/rfc6750#section-3.1
           If the request lacks any authentication information (e.g., the client
           was unaware that authentication is necessary or attempted using an
           unsupported authentication method), the resource server SHOULD NOT
           include an error code or other error information.
         */
        console.error("Auth headers non existant or malformed")
        res.sendStatus(401);
        return;
    }
    try {
        const token = authorisationHeader.replace("Bearer ", "");
        const {payload} = await jwtVerify(token, publicKey);
        const code = !!payload.preAuthorizedCode ?
            payload.preAuthorizedCode as string :
            payload.code as string;

        if(Date.now()/1000 > payload.exp){
            throw new Error(`Token expired`);
        }
        if(payload.iss !== issuer.issuerMetadata.credential_issuer){
            throw new Error("Invalid iss in token");
        }
        const offer = await issuer.credentialOfferSessions.get(code);
        if(!offer){
            throw new Error("Offer does not exist means that preAuthCode or code is invalid");
        }

    } catch (e){
        console.error(e)
        res.status(401).json({error:"invalid_token"});
        return;
    }

    const credentialReq = req.body as CredentialRequestV1_0_11;
    console.log('credential req', JSON.stringify(credentialReq, null, 2))

    // error cases
    // check credential request if it has required fields
    if( validateCredentialReq(credentialReq) ){
        res.setHeader('Cache-Control','no-store').status(400)
            .json({error:"invalid_credential_request"})
        return;
    }
    // check format, req format needs to be supported
    if( !issuer.issuerMetadata.credentials_supported.some(credentialSupported => {
        return credentialSupported.format === credentialReq.format
    })){
        res.setHeader('Cache-Control','no-store').status(400)
            .json({error:"unsupported_credential_format"})
        return;
    }
    // check type, every type need to be supported
    if(issuer.issuerMetadata.credentials_supported.some(credentialSupported => {
        return credentialReq["types"].every((type:string) => {
            return type in credentialSupported["types"]
        })
    })){
        res.setHeader('Cache-Control','no-store').status(400)
            .json({error:"unsupported_credential_type"})
        return;
    }
    // check encryption params
    // this demo doesnt encrypt credential request

    // https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-credential-issuer-provided-

    try {
        const credentialRes = await issuer.issueCredential({
            credentialRequest: credentialReq,
            credentialDataSupplier: credentialDataSupplier,
            cNonceExpiresIn: issuer.cNonceExpiresIn,
            tokenExpiresIn: 10 * 60 * 1000, //needs to be same as in /token
        });
        console.log('credential res', JSON.stringify(credentialRes, null, 2));
        res.json(credentialRes);
    } catch (e){
        console.error(e);
        res.setHeader('Cache-Control','no-store').status(500)
            .json({error:"server_error"})
    }
}