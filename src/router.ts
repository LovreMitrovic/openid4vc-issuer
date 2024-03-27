import express, { Request, Response } from 'express';
import {issuer, templateCredential} from "./issuer";
const router = express.Router();

router.get('/', (req: Request, res: Response) => {
    res.render('index')
});

router.get('/.well-known/openid-credential-issuer', (req, res) => {
    res.json(issuer.issuerMetadata);
});

router.get('/example-offer', async (req,res) => {
    const offerResult = await issuer.createCredentialOfferURI({
        grants: {
            'urn:ietf:params:oauth:grant-type:pre-authorized_code': {
                'pre-authorized_code': 'test-code',
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
    //res.json(offerResult);
    res.render('offer',offerResult)
})

export default router;
