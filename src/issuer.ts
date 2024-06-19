import {
    CredentialDataSupplier, CredentialDataSupplierResult, CredentialIssuanceInput,
    CredentialSupportedBuilderV1_11,
    VcIssuer,
    VcIssuerBuilder
} from "@sphereon/oid4vci-issuer";
import * as common from "@sphereon/oid4vci-common";
import {importJWK, jwtVerify, decodeProtectedHeader, importPKCS8, SignJWT} from "jose";
import {DIDDocument, UniResolver} from "@sphereon/did-uni-client";
import {JwtVerifyResult, OID4VCICredentialFormat, UniformCredentialRequest} from "@sphereon/oid4vci-common";
import jwtlib from "jsonwebtoken";
import {IIssuer, ICredentialSubject} from "@sphereon/ssi-types/dist/types/w3c-vc";

const credentialSupported = new CredentialSupportedBuilderV1_11()
    .withId('covid-passport')
    .withFormat('jwt_vc_json')
    //.withCryptographicBindingMethod('jwk')
    //.withCryptographicSuitesSupported('jwk_vc')
    .withTypes(["VerifiableCredential"])
    .withCredentialSupportedDisplay({
        name:"Covid Passort",
        locale:"en-US"
    })
    .build();

export const initIssuer = (url: string): VcIssuer<any> => {
    return new VcIssuerBuilder()
        .withAuthorizationServer(url)
        .withCredentialEndpoint(`${url}/credential`)
        .withCredentialIssuer(url)
        .withIssuerDisplay({
            name: 'Default issuer display',
            locale: 'en-US',
        })
        .withInMemoryCredentialOfferState()
        .withInMemoryCNonceState()
        .withCredentialsSupported(credentialSupported)
        .withJWTVerifyCallback(async ({jwt, kid}) => {
            try {
                const decodedJwt = decodeProtectedHeader(jwt);
                // resolving did
                const resolver = new UniResolver();
                const didResolutionResult = await resolver.resolve(kid === undefined ? decodedJwt.kid : kid);
                const {publicKeyJwk} = didResolutionResult.didDocument.verificationMethod[0];
                const publicKey = await importJWK(publicKeyJwk);
                // verify jwt
                const jwtObj = await jwtVerify(jwt, publicKey);
                console.log(`debug jwt decoded >${JSON.stringify(jwtObj)}<`);
                const header: common.JWTHeader = jwtObj.protectedHeader;
                const payload: common.JWTPayload = jwtObj.payload;
                const jwtVerifyResult = {
                    jwt: {
                        header,
                        payload
                    },
                    alg: header.alg,
                    didDocument: didResolutionResult.didDocument,
                    did: JSON.stringify(didResolutionResult.didDocument),
                    //jwk: publicKeyJwk
                }
                return new Promise((resolve, reject) => {
                    resolve(jwtVerifyResult)
                });
            } catch (e) {
                return new Promise((resolve, reject) => {
                    reject(e)
                });
            }
        })
        .withCredentialSignerCallback(async (opts) => {
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
        })
        .build()
}

export const credentialDataSupplier: CredentialDataSupplier = (args) => {
    console.log(args);
    const {credentialDataSupplierInput} = args;
    const payload = jwtlib.decode(args.credentialRequest.proof.jwt) as jwtlib.JwtPayload;
    const startTime = new Date();
    const endTime = new Date(startTime.getTime() + 2*60*60*1000); // 2 hours from startTime
    const credential = {
        '@context': [
            "https://www.w3.org/2018/credentials/v1"
        ],
        type: ['VerifiableCredential'],
        issuer: process.env.PUBLIC_KEY_DID,
        issuanceDate: startTime.toJSON(),
        expirationDate: endTime.toJSON(),
        credentialSubject: {
            "id": payload.iss,
            "manufacturer": credentialDataSupplierInput.manufacturer,
        }
    };
    const result: CredentialDataSupplierResult = {
        credential
    };
    return new Promise((resolve, reject) => resolve(result));
}