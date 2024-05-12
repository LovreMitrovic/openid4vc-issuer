import express, {Request, Response, Router} from 'express';
import {initIssuer, credentialDataSupplier} from "./issuer";
import {
    AccessTokenRequest,
    CredentialRequestV1_0_11,
    generateRandomString,
    GrantTypes,
    Jwt
} from "@sphereon/oid4vci-common";
import {createAccessTokenResponse, VcIssuer} from "@sphereon/oid4vci-issuer";
import jwtlib from "jsonwebtoken";
import {AssertedUniformCredentialOffer} from "@sphereon/oid4vci-common/dist/types/CredentialIssuance.types";
import {CredentialDataSupplierInput} from "@sphereon/oid4vci-common/dist/types/Generic.types";
import {CredentialOfferSession, IssueStatus} from "@sphereon/oid4vci-common/dist/types/StateManager.types";
import {randomBytes} from "node:crypto";
import {importJWK, importPKCS8, jwtVerify, KeyLike, SignJWT} from "jose";
import {UniResolver} from "@sphereon/did-uni-client";
const router = express.Router();


router.get('/', (req: Request, res: Response) => {
    res.render('index')
});

router.get('/.well-known/openid-credential-issuer', (req, res) => {
    const issuer = req.app.locals.issuer;
    res.json(issuer.issuerMetadata);
});

router.post('/offer', async (req,res) => {
    const issuer = req.app.locals.issuer as VcIssuer<object>;
    const data = req.body;

    if(!('manufacturer' in data) || Object.keys(data).length !== 1 ||
        (data.manufacturer !== "Blue Inc." && data.manufacturer !== "Red Inc.")){
            res.status(400).send('Error 400')
            return;
    }

    const codeLengthInBytes = !!parseInt(process.env.CODE_LENGTH) ? parseInt(process.env.CODE_LENGTH) : 16;
    const code: string = randomBytes(codeLengthInBytes).toString("hex");

    const pinLength = 4;
    const pad: string = "0".repeat(pinLength);
    let pin: string = (randomBytes(32).readUInt32BE() % 10**pinLength).toString();
    pin = pad.substring(0, pad.length - pin.length) + pin;

    const offerResult = await issuer.createCredentialOfferURI({
        grants: {
            'urn:ietf:params:oauth:grant-type:pre-authorized_code': {
                'pre-authorized_code': code,
                user_pin_required: true,
                // TODO tx-code eg pin ide zasebnim kanalom i služi za obranu replay napada
            },
        },
        credentials: ['covid-passport'],
        qrCodeOpts: {
            size: 400 // it will not work if it is small
        },
        pinLength: pinLength
    })

    const session: CredentialOfferSession = {
        createdAt: Date.now(),
        //clientId?: string;
        credentialOffer: {
            credential_offer: {
                credential_issuer: req.app.locals.issuer.credential_issuer,
                credentials: ['jwt_vc']
            }

        },
        credentialDataSupplierInput: data,
        userPin: pin,    // only when pin is required
        status: IssueStatus.OFFER_CREATED,
        //error?: string;
        lastUpdatedAt: Date.now(),
        //issuerState?: string;
        preAuthorizedCode: code
    };
    await issuer.credentialOfferSessions.set(code,session);
    //todo pošalji pin emailom

    //res.json(offerResult);
    res.render('offer',{...offerResult, pin})
})

router.post('/token', async (req, res) => {
    const issuer = req.app.locals.issuer as VcIssuer<object>;
    const tokenReq = req.body as AccessTokenRequest;
    console.log('token req', JSON.stringify(tokenReq, null, 2));

    // error cases
    if(!("grant_type" in tokenReq) ||
        "grant_type" in tokenReq && tokenReq.grant_type == GrantTypes.PRE_AUTHORIZED_CODE && !('user_pin' in tokenReq) ||
        "grant_type" in tokenReq && tokenReq.grant_type == GrantTypes.PRE_AUTHORIZED_CODE && !('pre-authorized_code' in tokenReq)){
        res.setHeader('Cache-Control','no-store').status(400)
            .json({error:"invalid_request"})
        return;
    }
    if(tokenReq.grant_type != GrantTypes.PRE_AUTHORIZED_CODE){
        res.setHeader('Cache-Control','no-store').status(400)
            .json({error:"unsupported_grant_type"}) // look at RFC 6749 OAuth 2.0
        return;
    }
    if(!('client_id' in tokenReq) /*&& usesPreAuthCodeFlow*/){
        res.setHeader('Cache-Control','no-store').status(400)
            .json({error:"invalid_client"})
        return;
    }
    const expiresIn = !!parseInt(process.env.CODE_EXPIRES_IN) ? parseInt(process.env.CODE_EXPIRES_IN) : 300;
    if(!(await issuer.credentialOfferSessions.has(tokenReq["pre-authorized_code"])) ||
        (await issuer.credentialOfferSessions.get(tokenReq["pre-authorized_code"])).createdAt + expiresIn > Date.now() ||
        (await issuer.credentialOfferSessions.get(tokenReq["pre-authorized_code"])).userPin !== tokenReq.user_pin){
        res.setHeader('Cache-Control','no-store').status(400)
            .json({error:"invalid_grant"})
        return;
    }

    // creating token response
    const accessTokenSignerCallback = async (jwt: Jwt): Promise<string> => {
        const pemPrivateKey =  Buffer.from(process.env.PRIVATE_KEY , 'base64').toString('ascii');
        const privateKey = await importPKCS8(pemPrivateKey, 'ES256');
        return new SignJWT(jwt.payload)
            .setProtectedHeader({alg:'ES256'})
            .setExpirationTime('30s') // anything above 5m is considered to be long lived
            .sign(privateKey)
    };
    try {
        const tokenRes = await createAccessTokenResponse(tokenReq, {
            credentialOfferSessions: issuer.credentialOfferSessions,
            cNonces: issuer.cNonces,
            //cNonce: 'c6c651e0-58a1-4299-a79a-f8841afe4a89', it defaults to v4()
            cNonceExpiresIn: issuer.cNonceExpiresIn,
            tokenExpiresIn: 10 * 60 * 1000,
            accessTokenSignerCallback,
            accessTokenIssuer: issuer.issuerMetadata.credential_issuer,
            interval: 3000
        });
        console.log('token res', JSON.stringify(tokenRes, null, 2));
        res.setHeader('Cache-Control', 'no-store').json(tokenRes);
    } catch(e){
        console.error(e);
        res.setHeader('Cache-Control','no-store').status(500)
            .json({error:"server_error"});
    }
})

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

router.post('/credential',async (req, res) => {
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
        const code = payload.preAuthorizedCode as string;

        if(Date.now()/1000 > payload.exp){
            throw new Error(`Token expired`);
        }
        if(payload.iss !== issuer.issuerMetadata.credential_issuer){
            throw new Error("Invalid iss in token");
        }
        const offer = await issuer.credentialOfferSessions.get(code);
        if(!offer){
            throw new Error("Offer does not exist means that preAuthCode is invalid");
        }
        // TODO implement preAuthCode <-> Credential data connection
        //  library offers this connection via CredentialOfferSession

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

    //TODO check if credential request has valid nounce in proof
    // library does this but it returns multiple diffrent
    // Error messages.
    // https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-credential-issuer-provided-

    try {
        const credentialRes = await issuer.issueCredential({
            credentialRequest: credentialReq,
            //credential: templateCredential(),
            credentialDataSupplier: credentialDataSupplier,
            //credentialDataSupplierInput?: CredentialDataSupplierInput;
            //newCNonce?: string;
            cNonceExpiresIn: issuer.cNonceExpiresIn,
            tokenExpiresIn: 10 * 60 * 1000, //can remove hardcoded value, need to be same as in /token
            //jwtVerifyCallback?: JWTVerifyCallback<DIDDoc>;
            //credentialSignerCallback?: CredentialSignerCallback<DIDDoc>;
            //responseCNonce?: string;
        });
        console.log('credential res', JSON.stringify(credentialRes, null, 2));
        res.json(credentialRes);
    } catch (e){
        console.error(e);
        res.setHeader('Cache-Control','no-store').status(500)
            .json({error:"server_error"})
    }
})

export default router;
