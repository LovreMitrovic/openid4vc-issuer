import dotenv from "dotenv";
import nodemailer from "nodemailer";

export async function sendEmail(destination: string, pin: string){
    let transporter = nodemailer.createTransport({
        service: "Outlook365",
        host: "outlook.office365.com",
        port: 993,
        auth: {
            user: process.env.EMAIL_USER,
            pass: process.env.EMAIL_PASS
        },
        tls: {
            ciphers:'SSLv3'
        }
    });

    return await transporter.sendMail({
        from: process.env.EMAIL_USER,
        to: destination,
        subject: 'Pin for https://openid4vc-issuer.onrender.com',
        text: `Your pin is ${pin}`
    })
}
