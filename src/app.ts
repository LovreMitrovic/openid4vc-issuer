import dotenv from 'dotenv';
import express from 'express';
import indexRouter from './router';
import path from "node:path";
dotenv.config();

const externalUrl = process.env.RENDER_EXTERNAL_URL;
const port = /*externalUrl &&*/ process.env.PORT ? parseInt(process.env.PORT) : 3000;

const app = express();

app.set('view engine','ejs');
app.set('views', path.join(__dirname, 'views'))

app.use('/', indexRouter);

if(externalUrl){
    const hostname = '0.0.0.0';
    app.listen(port, hostname, () => {
        console.log(`Server is running locally on http://${hostname}:${port}/ and from outside on ${externalUrl}`);
    });
} else {
    const os = require('os');
    const networkInterfaces = os.networkInterfaces();
    const hostname = networkInterfaces['wlo1'].filter((obj)=>obj['family']=='IPv4')[0]['address'];
    app.listen(port, () => {
        console.log(`Server is running locally on http://${hostname}:${port}/ `);
    });
}