import {decodeProtectedHeader, importJWK} from "jose";
import {UniResolver} from "@sphereon/did-uni-client";
import * as common from "@sphereon/oid4vci-common";
import {jwtVerify} from "jose";

export const jwtVerifyCallback = async ({jwt, kid}) => {
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
            did: JSON.stringify(didResolutionResult.didDocument)
        }
        return new Promise((resolve, reject) => {
            resolve(jwtVerifyResult)
        });
    } catch (e) {
        return new Promise((resolve, reject) => {
            reject(e)
        });
    }
}