import express, {request, Request, Response, Router} from 'express';
import {initIssuer, credentialDataSupplier} from "./issuer";
import {
    AccessTokenRequest, AuthorizationRequest,
    CredentialRequestV1_0_11,
    generateRandomString,
    GrantTypes,
    Jwt, PRE_AUTH_CODE_LITERAL, TokenError
} from "@sphereon/oid4vci-common";
import {VcIssuer} from "@sphereon/oid4vci-issuer";
import jwtlib from "jsonwebtoken";
import {AssertedUniformCredentialOffer} from "@sphereon/oid4vci-common/dist/types/CredentialIssuance.types";
import {CredentialDataSupplierInput} from "@sphereon/oid4vci-common/dist/types/Generic.types";
import {CredentialOfferSession, IssueStatus} from "@sphereon/oid4vci-common/dist/types/StateManager.types";
import {randomBytes} from "node:crypto";
import {importJWK, importPKCS8, jwtVerify, KeyLike, SignJWT} from "jose";
import {UniResolver} from "@sphereon/did-uni-client";
import {assertValidAccessTokenRequest, createAccessTokenResponse} from "./utils/token";
import {sendEmail} from "./service/sendEmail";
import validator from "validator";
const router = express.Router();


router.get('/', (req: Request, res: Response) => {
    res.render('index')
});

router.get('/.well-known/openid-credential-issuer', (req, res) => {
    const issuer = req.app.locals.issuer;
    const url = req.app.locals.url;
    res.json({...issuer.issuerMetadata, authorization_endpoint: `${url}/authorize`});
});

router.post('/offer-preauth', async (req,res) => {
    const issuer = req.app.locals.issuer as VcIssuer<object>;
    const data = req.body;

    if(!('manufacturer' in data) ||
        !('email' in data) ||
        Object.keys(data).length !== 2 ||
        !validator.isEmail(data.email) ||
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

    const grants = {
        'urn:ietf:params:oauth:grant-type:pre-authorized_code': {
            'pre-authorized_code': code,
            user_pin_required: true,
            // TODO tx-code eg pin ide zasebnim kanalom i služi za obranu replay napada
        },
    };

    const offerResult = await issuer.createCredentialOfferURI({
        grants,
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
                credentials: ['jwt_vc'],
                grants
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
    try{
        await sendEmail(data.email, pin);
    } catch (e) {
        res.status(500).send(`Email could not be sent!`);
        console.error(e);
        return;
    }

    res.render('offer',offerResult);
})

router.post('/offer-auth', async (req,res) => {
    const issuer = req.app.locals.issuer as VcIssuer<object>;

    const issuerState: string = randomBytes(32).toString("hex");

    const grants = {
        authorization_code: {
            issuer_state: issuerState
        }
    };

    const offerResult = await issuer.createCredentialOfferURI({
        grants,
        credentials: ['covid-passport'],
        qrCodeOpts: {
            size: 400 // it will not work if it is small
        }
    })

    const session: CredentialOfferSession = {
        createdAt: Date.now(),
        //clientId?: string;
        credentialOffer: {
            credential_offer: {
                credential_issuer: req.app.locals.issuer.credential_issuer,
                credentials: ['jwt_vc'],
                grants
            }

        },
        //credentialDataSupplierInput: data will be supplied when user is auth
        //userPin: pin,    // only when pin is required
        status: IssueStatus.OFFER_CREATED,
        //error?: string;
        lastUpdatedAt: Date.now(),
        issuerState: issuerState,
        //preAuthorizedCode: code
    };
    await issuer.credentialOfferSessions.set(issuerState,session);

    res.render('offer',offerResult);
})

/*
    This is out of scope of specs OID4VCI, OID Connect and OAuth 2.0
    Implementation using hardcoded username and password and
    use of HTTP Basic is chosen because of simplicity.
 */
router.get('/authorize', async (req, res) => {
    const issuer = req.app.locals.issuer as VcIssuer<object>;
    const url = req.app.locals.url as string;
    const authReq = req.query as unknown as AuthorizationRequest;
    console.log('auth req', JSON.stringify(authReq, null, 2));

    // invalid_request rfc7636
    if(!authReq["code_challenge"] &&
        !authReq["code_challenge_method"] &&
        authReq["code_challenge_method"] !== "S256"){
        res.status(400).json({error: "invalid_request"});
        return;
    }

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
    //await issuer.credentialOfferSessions.set(code, {...offerSession, credentialDataSupplierInput: data});
    await issuer.credentialOfferSessions.set(code, {...offerSession,
        credentialDataSupplierInput: data,
        // @ts-ignore
        code_challange: authReq.code_challenge,
        code_challenge_method:authReq.code_challenge_method,
        code
    });

    console.log(`redirect with code ${code}`)
    res.redirect(`${authReq.redirect_uri}/?code=${code}`);
})

router.post('/token', async (req, res) => {
    const issuer = req.app.locals.issuer as VcIssuer<object>;
    const tokenReq = req.body as AccessTokenRequest;
    console.log('token req', JSON.stringify(tokenReq, null, 2));

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
        await assertValidAccessTokenRequest(tokenReq, {
            credentialOfferSessions: issuer.credentialOfferSessions,
            expirationDuration: 10 * 60 * 1000
        });
        const tokenRes = await createAccessTokenResponse(tokenReq, {
            credentialOfferSessions: issuer.credentialOfferSessions,
            cNonces: issuer.cNonces,
            cNonceExpiresIn: issuer.cNonceExpiresIn,
            tokenExpiresIn: 10 * 60 * 1000,
            accessTokenSignerCallback,
            accessTokenIssuer: issuer.issuerMetadata.credential_issuer,
            interval: 3000
        });
        console.log('token res', JSON.stringify(tokenRes, null, 2));
        res.setHeader('Cache-Control', 'no-store').json(tokenRes);
    } catch (e){
        console.error(e);
        if(e instanceof TokenError){
            res.setHeader('Cache-Control','no-store').status(e.statusCode)
                .json({error:e.responseError});
            return;
        }
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
