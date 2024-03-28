import express, {Request, Response, Router} from 'express';
import {initIssuer, templateCredential} from "./issuer";
import {AccessTokenRequest, CredentialRequestV1_0_11, Jwt} from "@sphereon/oid4vci-common";
import {createAccessTokenResponse} from "@sphereon/oid4vci-issuer";
import jwtlib from "jsonwebtoken";
import {AssertedUniformCredentialOffer} from "@sphereon/oid4vci-common/dist/types/CredentialIssuance.types";
import {CredentialDataSupplierInput} from "@sphereon/oid4vci-common/dist/types/Generic.types";
import {CredentialOfferSession, IssueStatus} from "@sphereon/oid4vci-common/dist/types/StateManager.types";
const router = express.Router();


router.get('/', (req: Request, res: Response) => {
    res.render('index')
});

router.get('/.well-known/openid-credential-issuer', (req, res) => {
    const issuer = req.app.locals.issuer;
    res.json(issuer.issuerMetadata);
});

router.get('/example-offer', async (req,res) => {
    const issuer = req.app.locals.issuer;

    const offerResult = await issuer.createCredentialOfferURI({
        grants: {
            'urn:ietf:params:oauth:grant-type:pre-authorized_code': {
                'pre-authorized_code': 'test-code',//TODO pre-auth code treba biti short-lived
                user_pin_required: false,
                // TODO tx-code eg pin ide zasebnim kanalom i služi za obranu replay napada
            },
        },
        credentials: ['covid-passport'],
        qrCodeOpts: {
            // it wont work if it is small
            size: 400
        }
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
        //credentialDataSupplierInput?: CredentialDataSupplierInput;
        //userPin?: string;
        status: IssueStatus.OFFER_CREATED,
        //error?: string;
        lastUpdatedAt: Date.now(),
        //issuerState?: string;
        preAuthorizedCode: 'test-code'
    };
    issuer.credentialOfferSessions.set('test-code',session);

    //res.json(offerResult);
    res.render('offer',offerResult)
})

router.post('/token', async (req, res) => {
    const issuer = req.app.locals.issuer;
    const tokenReq = req.body as AccessTokenRequest;
    console.log('token req', JSON.stringify(tokenReq, null, 2));
    //TODO ako ne zadovoljava formu vrati 400

    const accessTokenSignerCallback = async (jwt: Jwt): Promise<string> => {
        const symmetricKey = req.app.locals.symmetricKey;
        return jwtlib.sign(jwt.payload, symmetricKey);
    };

    // TODO ako pukne vrati error, treba provjeriti u docs jeli metoda gleda je li code expired
    const tokenRes = await createAccessTokenResponse(tokenReq, {
        credentialOfferSessions: issuer.credentialOfferSessions,
        cNonces: issuer.cNonces,
        cNonce: 'c6c651e0-58a1-4299-a79a-f8841afe4a89',//TODO replace with v4(),
        cNonceExpiresIn: issuer.cNonceExpiresIn,
        tokenExpiresIn: 300,
        accessTokenSignerCallback,
        accessTokenIssuer: issuer.issuerMetadata.credential_issuer,
        interval: 3000
    });
    console.log('token res', JSON.stringify(tokenRes, null, 2));
    res.setHeader('Cache-Control','no-store').json(tokenRes);
})

router.post('/credential', async (req, res) => {
    // TODO provjeri autorizaciju tokena, je li istekao, je li potpisan i sadrži li ispravan code?
    // TODO postoji veza token <-> credential
    const issuer = req.app.locals.issuer;
    const credentialReq = req.body as CredentialRequestV1_0_11;
    console.log('credential req', JSON.stringify(credentialReq, null, 2))
    const credentialRes = await issuer.issueCredential({
        credentialRequest: credentialReq,
        credential: templateCredential(),
        //credentialDataSupplier?: CredentialDataSupplier;
        //credentialDataSupplierInput?: CredentialDataSupplierInput;
        //newCNonce?: string;
        cNonceExpiresIn: issuer.cNonceExpiresIn,
        tokenExpiresIn: 300, //TODO remove hardcoded value, need to be same as in /token
        //jwtVerifyCallback?: JWTVerifyCallback<DIDDoc>;
        //credentialSignerCallback?: CredentialSignerCallback<DIDDoc>;
        //responseCNonce?: string;
    });
    console.log('credential res', JSON.stringify(credentialRes, null, 2));
    res.json(credentialRes);
})

export default router;
