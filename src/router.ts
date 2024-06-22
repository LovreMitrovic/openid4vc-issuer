import express from 'express';
import {offerPreauthController} from "./controllers/offer-preauth.controller";
import {offerAuthController} from "./controllers/offer-auth.controller";
import {authorizeController} from "./controllers/authorize.controller";
import {tokenController} from "./controllers/token.controller";
import {credentialController} from "./controllers/credential.controller";
const router = express.Router();

router.get('/.well-known/openid-credential-issuer', (req, res) => {
    const issuer = req.app.locals.issuer;
    const url = req.app.locals.url;
    res.json({...issuer.issuerMetadata, authorization_endpoint: `${url}/authorize`});
});

router.post('/offer-preauth', offerPreauthController);

router.post('/offer-auth', offerAuthController);

router.get('/authorize', authorizeController);

router.post('/token', tokenController);

router.post('/credential',credentialController);

export default router;
