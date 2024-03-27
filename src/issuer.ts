import {CredentialSupportedBuilderV1_11, VcIssuerBuilder} from "@sphereon/oid4vci-issuer";
import * as common from "@sphereon/oid4vci-common";
import {jwtVerify, importSPKI, exportJWK, SignJWT,importPKCS8} from "jose";
import fs from "fs";
import crypto from "crypto";
import path from "node:path";

const credentialSupported = new CredentialSupportedBuilderV1_11()
    .withId('covid-passport')
    .withFormat('jwt_vc_json')
    //.withCryptographicBindingMethod('jwk')
    //.withCryptographicSuitesSupported('jwk_vc')
    .withTypes(["VerifiableCredential", "CovidPassportCredential"])
    .withCredentialSupportedDisplay({
        name:"Covid Passort",
        locale:"en-US"
    })
    .build();

export const issuer = new VcIssuerBuilder()
    .withUserPinRequired(false)
    .withAuthorizationServer('https://localhost/')
    .withCredentialEndpoint('https://localhost/credential')
    .withCredentialIssuer('https://localhost/')
    .withIssuerDisplay({
        name: 'Default issuer display',
        locale: 'en-US',
    })
    .withInMemoryCredentialOfferState()
    .withInMemoryCNonceState()
    .withCredentialsSupported(credentialSupported)
    .withJWTVerifyCallback(async ({jwt, kid})=>{
        const pemPublicKey = fs.readFileSync(
            path.join(process.cwd(), "/dist/wallet/public.pem"),"ascii");
        // TODO ovdje se gleda jwt potpisan od walleta koristi did umjesto filea
        const publicKey = await importSPKI(pemPublicKey,'ES256');
        const jwtObj = await jwtVerify(jwt,publicKey);
        console.log(`debug jwt decoded >${JSON.stringify(jwtObj)}<`);
        const header: common.JWTHeader = {
            alg: jwtObj.protectedHeader.alg,
            typ: "openid4vci-proof+jwt"
        }
        const payload: common.JWTPayload = jwtObj.payload;
        const result = {
            jwt: {
                header,
                payload
            },
            alg: header.alg,
            jwk: await exportJWK(publicKey),
            // TODO dohvati preko did a ne preko filea
            // za ovaj key material vežem credential
        }
        return new Promise((resolve,reject) => {resolve(result)});
    })
    // TODO .withCredentialSignerCallback()
    .withCredentialSignerCallback(async (opts) => {
        console.log(`debug signing credential >${JSON.stringify(opts,null,4)}<`)
        const {credential,
            credentialRequest,
            format,
            jwtVerifyResult} = opts;
        const payload = {
            vc: credential,
            iss: credential.issuer,
            sub: jwtVerifyResult.jwt.payload.iss
        }
        const header ={
            alg: jwtVerifyResult.alg,
            typ: "JWT"
        }

        const pemPrivateKey = fs.readFileSync(
            path.join(process.cwd(), "/dist/issuer/private.pem"),"ascii");
        const privateKey = await importPKCS8(pemPrivateKey,'ES256');

        // @ts-ignore
        const credentialJwt: string = await new SignJWT(payload)
            .setProtectedHeader({alg: jwtVerifyResult.alg})
            .setIssuedAt()
            .setIssuer('https://localhost/')
            // @ts-ignore
            .setSubject(jwtVerifyResult.jwt.payload.iss)
            .setExpirationTime('2h')
            .sign(privateKey);
        //TODO OVDJE potreban proof field u credential kako bi bio verifiable za W3C VC
        return new Promise((resolve,reject) => {resolve(credentialJwt)})
    })
    .build()

export const templateCredential = {
    '@context': [
        "https://www.w3.org/2018/credentials/v1",
        "https://www.w3.org/2018/credentials/examples/v1"
    ],
    type: ['CovidPassportCredential','VerifiableCredential'],
    issuer: "https://localhost/",
    issuanceDate: '20-20-2020',
    credentialSubject: {
        "id": "did:web:about.lovremitrovic.me:did-database:wallet",
        "manufacturer": "Covid Vaccines Croatia Inc.",
        "valid": "10-10-2030"
    }
};