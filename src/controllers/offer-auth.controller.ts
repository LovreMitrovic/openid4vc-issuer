import {VcIssuer} from "@sphereon/oid4vci-issuer";
import {randomBytes} from "node:crypto";
import {CredentialOfferSession, IssueStatus} from "@sphereon/oid4vci-common/dist/types/StateManager.types";

export const offerAuthController = async (req,res) => {
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
        credentialOffer: {
            credential_offer: {
                credential_issuer: req.app.locals.issuer.credential_issuer,
                credentials: ['jwt_vc'],
                grants
            }

        },
        status: IssueStatus.OFFER_CREATED,
        lastUpdatedAt: Date.now(),
        issuerState: issuerState,
    };
    await issuer.credentialOfferSessions.set(issuerState,session);

    res.render('offer',offerResult);
}