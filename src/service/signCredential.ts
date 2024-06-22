import {importPKCS8, SignJWT} from "jose";
import {ICredentialSubject} from "@sphereon/ssi-types/dist/types/w3c-vc";

export const signCredentialCallback = async (opts) => {
    console.log(`debug signing credential >${JSON.stringify(opts, null, 4)}<`)
    const {
        credential,
        credentialRequest,
        format,
        jwtVerifyResult
    } = opts;
    const payload = {
        vc: credential,
    }
    const header = {
        alg: "ES256",
        typ: "JWT"
    }

    const pemPrivateKey =  Buffer.from(process.env.PRIVATE_KEY , 'base64').toString('ascii');
    const privateKey = await importPKCS8(pemPrivateKey, 'ES256');
    // @ts-ignore
    const credentialJwt: string = await new SignJWT(payload)
        .setProtectedHeader(header)
        .setIssuer(credential.issuer as string)
        .setNotBefore( (new Date(credential.issuanceDate as string)).getTime()/1000 )
        .setExpirationTime( (new Date(credential.expirationDate as string)).getTime()/1000 )
        .setSubject((credential.credentialSubject as ICredentialSubject).id)
        .sign(privateKey);
    return new Promise((resolve, reject) => {
        resolve(credentialJwt)
    })
}