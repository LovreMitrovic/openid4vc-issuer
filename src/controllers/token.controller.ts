import {VcIssuer} from "@sphereon/oid4vci-issuer";
import {AccessTokenRequest, Jwt, TokenError} from "@sphereon/oid4vci-common";
import {importPKCS8, SignJWT} from "jose";
import {assertValidAccessTokenRequest, createAccessTokenResponse} from "../utils/token";

export const tokenController = async (req, res) => {
    const issuer = req.app.locals.issuer as VcIssuer<object>;
    const tokenReq = req.body as AccessTokenRequest;
    console.log('token req', JSON.stringify(tokenReq, null, 2));

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
}