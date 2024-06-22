import {VcIssuer} from "@sphereon/oid4vci-issuer";
import validator from "validator";
import {randomBytes} from "node:crypto";
import {CredentialOfferSession, IssueStatus} from "@sphereon/oid4vci-common/dist/types/StateManager.types";
import {sendEmail} from "../service/sendEmail";

export const offerPreauthController = async (req,res) => {
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
        lastUpdatedAt: Date.now(),
        preAuthorizedCode: code
    };
    await issuer.credentialOfferSessions.set(code,session);

    try{
        await sendEmail(data.email, pin);
    } catch (e) {
        res.status(500).send(`Email could not be sent!`);
        console.error(e);
        return;
    }

    res.render('offer',offerResult);
}