/*
    This code is copied from @sphereon/oid4vci-issuer library
    Im using it to add auth code
 */

import {
    AccessTokenRequest,
    AccessTokenResponse,
    Alg,
    CNonceState,
    CredentialOfferSession,
    EXPIRED_PRE_AUTHORIZED_CODE,
    GrantTypes,
    INVALID_PRE_AUTHORIZED_CODE,
    IssueStatus,
    IStateManager,
    Jwt,
    JWTSignerCallback,
    PIN_NOT_MATCH_ERROR,
    PIN_VALIDATION_ERROR,
    PRE_AUTH_CODE_LITERAL,
    PRE_AUTHORIZED_CODE_REQUIRED_ERROR,
    TokenError,
    TokenErrorResponse,
    UNSUPPORTED_GRANT_TYPE_ERROR,
    USER_PIN_NOT_REQUIRED_ERROR,
    USER_PIN_REQUIRED_ERROR,
} from '@sphereon/oid4vci-common'
import {v4} from 'uuid'

import {isPreAuthorizedCodeExpired} from '@sphereon/oid4vci-issuer'
import {base64url} from "jose";
import * as crypto from "node:crypto";

export interface ITokenEndpointOpts {
    tokenEndpointDisabled?: boolean // Disable if used in an existing OAuth2/OIDC environment and have the AS handle tokens
    tokenPath?: string // token path can either be defined here, or will be deduced from issuer metadata
    interval?: number
    cNonceExpiresIn?: number
    tokenExpiresIn?: number
    preAuthorizedCodeExpirationDuration?: number
    accessTokenSignerCallback?: JWTSignerCallback
    accessTokenIssuer?: string
}

export const generateAccessToken = async (
    opts: Required<Pick<ITokenEndpointOpts, 'accessTokenSignerCallback' | 'tokenExpiresIn' | 'accessTokenIssuer'>> & {
        preAuthorizedCode?: string,
        code?: string,
        alg?: Alg
    },
): Promise<string> => {
    const { accessTokenIssuer, alg, accessTokenSignerCallback, tokenExpiresIn, preAuthorizedCode, code } = opts
    // JWT uses seconds for iat and exp
    const iat = new Date().getTime() / 1000
    const exp = iat + tokenExpiresIn
    const jwt: Jwt = {
        header: { typ: 'JWT', alg: alg ?? Alg.ES256K },
        payload: {
            iat,
            exp,
            iss: accessTokenIssuer,
            ...(preAuthorizedCode && { preAuthorizedCode }),
            ...(code && {code})
        },
    }
    return await accessTokenSignerCallback(jwt)
}

export const isValidGrant = (assertedState: CredentialOfferSession, grantType: string, codeVerifier?: string): boolean => {
    if (assertedState.credentialOffer?.credential_offer?.grants) {
        return (
            Object.keys(assertedState.credentialOffer?.credential_offer?.grants).includes(GrantTypes.PRE_AUTHORIZED_CODE) &&
            grantType === GrantTypes.PRE_AUTHORIZED_CODE ||
            // my code
            Object.keys(assertedState.credentialOffer?.credential_offer?.grants).includes(GrantTypes.AUTHORIZATION_CODE) &&
            grantType === GrantTypes.AUTHORIZATION_CODE &&
                /*
                rfc7636 says If the values are not
                   equal, an error response indicating "invalid_grant" as described in
                   Section 5.2 of [RFC6749] MUST be returned.
                   BASE64URL-ENCODE(SHA256(ASCII(code_verifier))) == code_challenge
                 */
            // @ts-ignore
            assertedState.code_challange == base64url.encode(crypto.createHash('sha256').update(codeVerifier).digest())

        )
    }
    return false
}

export const assertValidAccessTokenRequest = async (
    request: Omit<AccessTokenRequest, "pre-authorized_code">,
    opts: {
        credentialOfferSessions: IStateManager<CredentialOfferSession>
        expirationDuration: number
    },
) => {
    const { credentialOfferSessions, expirationDuration } = opts
    // Only pre-auth supported for now
    if (request.grant_type !== GrantTypes.PRE_AUTHORIZED_CODE && request.grant_type !== GrantTypes.AUTHORIZATION_CODE) {
        throw new TokenError(400, TokenErrorResponse.invalid_grant, UNSUPPORTED_GRANT_TYPE_ERROR)
    }

    /*
        error cases
        also look at RFC 6749 OAuth 2.0
    */

    // Pre-auth flow
    if(request.grant_type === GrantTypes.PRE_AUTHORIZED_CODE) {
        if (!request[PRE_AUTH_CODE_LITERAL]) {
            throw new TokenError(400, TokenErrorResponse.invalid_request, PRE_AUTHORIZED_CODE_REQUIRED_ERROR)
        }

        const credentialOfferSession = await credentialOfferSessions.getAsserted(request[PRE_AUTH_CODE_LITERAL])
        credentialOfferSession.status = IssueStatus.ACCESS_TOKEN_REQUESTED
        credentialOfferSession.lastUpdatedAt = +new Date()
        await credentialOfferSessions.set(request[PRE_AUTH_CODE_LITERAL], credentialOfferSession)
        if (!isValidGrant(credentialOfferSession, request.grant_type)) {
            throw new TokenError(400, TokenErrorResponse.invalid_grant, UNSUPPORTED_GRANT_TYPE_ERROR)
        }
        /*
        invalid_request:
        the Authorization Server expects a PIN in the pre-authorized flow but the client does not provide a PIN
         */
        if (credentialOfferSession.credentialOffer.credential_offer?.grants?.[GrantTypes.PRE_AUTHORIZED_CODE]?.user_pin_required && !request.user_pin) {
            throw new TokenError(400, TokenErrorResponse.invalid_request, USER_PIN_REQUIRED_ERROR)
        }
        /*
        invalid_request:
        the Authorization Server does not expect a PIN in the pre-authorized flow but the client provides a PIN
         */
        if (!credentialOfferSession.credentialOffer.credential_offer?.grants?.[GrantTypes.PRE_AUTHORIZED_CODE]?.user_pin_required && request.user_pin) {
            throw new TokenError(400, TokenErrorResponse.invalid_request, USER_PIN_NOT_REQUIRED_ERROR)
        }
        /*
        invalid_grant:
        the Authorization Server expects a PIN in the pre-authorized flow but the client provides the wrong PIN
        the End-User provides the wrong Pre-Authorized Code or the Pre-Authorized Code has expired
         */
        if (request.user_pin && !/[0-9{,8}]/.test(request.user_pin)) {
            throw new TokenError(400, TokenErrorResponse.invalid_grant, PIN_VALIDATION_ERROR)
        } else if (request.user_pin !== credentialOfferSession.userPin) {
            throw new TokenError(400, TokenErrorResponse.invalid_grant, PIN_NOT_MATCH_ERROR)
        } else if (isPreAuthorizedCodeExpired(credentialOfferSession, expirationDuration)) {
            throw new TokenError(400, TokenErrorResponse.invalid_grant, EXPIRED_PRE_AUTHORIZED_CODE)
        } else if (
            request[PRE_AUTH_CODE_LITERAL] !==
            credentialOfferSession.credentialOffer?.credential_offer?.grants?.[GrantTypes.PRE_AUTHORIZED_CODE]?.[PRE_AUTH_CODE_LITERAL]
        ) {
            throw new TokenError(400, TokenErrorResponse.invalid_grant, INVALID_PRE_AUTHORIZED_CODE)
        }
        return {preAuthSession: credentialOfferSession}
    }
    // my code
    // Auth code flow
    /*
        invalid_request rfc6749
        The request is missing a required parameter other than grant type
     */
    if(!request["code"] && !request["code_verifier"] && !request["redirect_uri"]
        && !request["client_id"]){
        throw new TokenError(400, TokenErrorResponse.invalid_request, "Missing parametars")
    }
    const credentialOfferSession = await credentialOfferSessions.getAsserted(request["code"])
    credentialOfferSession.status = IssueStatus.ACCESS_TOKEN_REQUESTED;
    credentialOfferSession.lastUpdatedAt = +new Date();
    await credentialOfferSessions.set(request["code"], credentialOfferSession)
    /*
        invalid_grant
     */
    if (!isValidGrant(credentialOfferSession, request.grant_type, request["code_verifier"])) {
        throw new TokenError(400, TokenErrorResponse.invalid_grant, UNSUPPORTED_GRANT_TYPE_ERROR)
    }
    return {authSession: credentialOfferSession}
}

export const createAccessTokenResponse = async (
    request: AccessTokenRequest,
    opts: {
        credentialOfferSessions: IStateManager<CredentialOfferSession>
        cNonces: IStateManager<CNonceState>
        cNonce?: string
        cNonceExpiresIn?: number // expiration in seconds
        tokenExpiresIn: number // expiration in seconds
        // preAuthorizedCodeExpirationDuration?: number
        accessTokenSignerCallback: JWTSignerCallback
        accessTokenIssuer: string
        interval?: number
    },
) => {
    const { credentialOfferSessions, cNonces, cNonceExpiresIn, tokenExpiresIn, accessTokenIssuer, accessTokenSignerCallback, interval } = opts

    if(request.grant_type === GrantTypes.PRE_AUTHORIZED_CODE) {
        const preAuthorizedCode = request[PRE_AUTH_CODE_LITERAL] as string;

        const cNonce = opts.cNonce ?? v4()
        await cNonces.set(cNonce, {cNonce, createdAt: +new Date(), preAuthorizedCode})

        const access_token = await generateAccessToken({
            tokenExpiresIn,
            accessTokenSignerCallback,
            preAuthorizedCode,
            accessTokenIssuer,
        })
        const response: AccessTokenResponse = {
            access_token,
            token_type: 'bearer',
            expires_in: tokenExpiresIn,
            c_nonce: cNonce,
            c_nonce_expires_in: cNonceExpiresIn,
            authorization_pending: false,
            interval,
        }
        const credentialOfferSession = await credentialOfferSessions.getAsserted(preAuthorizedCode)
        credentialOfferSession.status = IssueStatus.ACCESS_TOKEN_CREATED
        credentialOfferSession.lastUpdatedAt = +new Date()
        await credentialOfferSessions.set(preAuthorizedCode, credentialOfferSession)
        return response
    }
    //auth code
    const code = request["code"] as string;
    const credentialOfferSession = await credentialOfferSessions.getAsserted(code);
    const issuerState = credentialOfferSession.issuerState;

    const cNonce = opts.cNonce ?? v4()
    await cNonces.set(cNonce, {cNonce, createdAt: +new Date(), issuerState});

    const access_token = await generateAccessToken({
        tokenExpiresIn,
        accessTokenSignerCallback,
        //preAuthorizedCode,
        code,
        accessTokenIssuer,
    })
    const response: AccessTokenResponse = {
        access_token,
        token_type: 'bearer',
        expires_in: tokenExpiresIn,
        c_nonce: cNonce,
        c_nonce_expires_in: cNonceExpiresIn,
        authorization_pending: false,
        interval,
    }
    credentialOfferSession.status = IssueStatus.ACCESS_TOKEN_CREATED
    credentialOfferSession.lastUpdatedAt = +new Date()
    // @ts-ignore
    await credentialOfferSessions.set(credentialOfferSession.issuerState, credentialOfferSession)
    //await credentialOfferSessions.delete(code);
    return response
}