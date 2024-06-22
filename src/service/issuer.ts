import {
    CredentialDataSupplier, CredentialDataSupplierResult, CredentialSignerCallback,
    CredentialSupportedBuilderV1_11,
    VcIssuer,
    VcIssuerBuilder
} from "@sphereon/oid4vci-issuer";
import jwtlib from "jsonwebtoken";
import {jwtVerifyCallback} from "./jwtVerify";
import {JWTVerifyCallback} from "@sphereon/oid4vci-common";
import {signCredentialCallback} from "./signCredential";

const credentialSupported = new CredentialSupportedBuilderV1_11()
    .withId('covid-passport')
    .withFormat('jwt_vc_json')
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
        .withJWTVerifyCallback(jwtVerifyCallback as JWTVerifyCallback<any>)
        .withCredentialSignerCallback(signCredentialCallback as CredentialSignerCallback<any>)
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