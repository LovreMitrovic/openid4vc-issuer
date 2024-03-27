const fs = require('fs');
const jose = require('jose');
const path = require('path');


const generateKeys = async (alg) => {
    console.log(`Generating keys using alg:${alg}`)
    const {privateKey, publicKey} = await jose.generateKeyPair(alg);
    const publicPem = await jose.exportSPKI(publicKey);
    const privatePem = await jose.exportPKCS8(privateKey);
    const privatePemB64 = Buffer.from(privatePem).toString('base64');
    const publicJwk = JSON.stringify(await jose.exportJWK(publicKey),null,2);
    const privateJwk = JSON.stringify(await jose.exportJWK(privateKey),null,2);

    const dir = './keys';
    if (!fs.existsSync(dir)){
        fs.mkdirSync(dir);
    }

    fs.writeFileSync(path.join(process.cwd(), `./keys/public.pem`), publicPem);
    fs.writeFileSync(path.join(process.cwd(), `./keys/private.pem`), privatePem);
    /*
        Put in ENV variable then use as
        const key = Buffer.from(process.env.PRIVATE_KEY , 'base64').toString('ascii');
    */
    fs.writeFileSync(path.join(process.cwd(), `./keys/private-pem-b64.txt`), privatePemB64);
    fs.writeFileSync(path.join(process.cwd(), `./keys/public.jwk.json`),publicJwk);
    fs.writeFileSync(path.join(process.cwd(), `./keys/private.jwk.json`),privateJwk);
};

generateKeys('ES256')
.then(()=>console.log('Keys generated'))
.catch((e)=>console.log(e))