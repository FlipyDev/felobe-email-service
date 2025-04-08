// server.js
require('dotenv').config(); // Carga .env en desarrollo

const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const Imap = require('node-imap');
const nodemailer = require('nodemailer');

const app = express();
app.use(bodyParser.json());
app.use(cors());

// Variables de entorno o valores por defecto
const DEFAULT_EMAIL_USER = process.env.EMAIL_USER || 'felobe@felobe.com';
const IMAP_HOST = process.env.IMAP_HOST || 'felobe.com';
const IMAP_PORT = process.env.IMAP_PORT ? parseInt(process.env.IMAP_PORT) : 993;
const IMAP_TLS = process.env.IMAP_TLS === 'true';
const SMTP_HOST = process.env.SMTP_HOST || IMAP_HOST;
const SMTP_PORT = process.env.SMTP_PORT ? parseInt(process.env.SMTP_PORT) : 465;

/**
 * Función que crea una conexión IMAP usando el correo y la contraseña enviados.
 */
function getImapConnection(emailUser, password) {
  const config = {
    user: emailUser,
    password: password,
    host: IMAP_HOST,
    port: IMAP_PORT,
    tls: IMAP_TLS
  };
  return new Imap(config);
}

/**
 * Endpoint: GET /api/email/inbox
 * Requiere en los headers:
 *   - x-email-user (opcional, se usa DEFAULT_EMAIL_USER si no se envía)
 *   - x-email-password (obligatorio)
 * Opcionales: page y perPage en query.
 */
app.get('/api/email/inbox', (req, res) => {
  const emailUser = req.headers['x-email-user'] || DEFAULT_EMAIL_USER;
  const password = req.headers['x-email-password'];
  if (!password) {
    return res.status(400).json({ error: 'Falta el header x-email-password' });
  }
  
  const imap = getImapConnection(emailUser, password);
  
  imap.once('ready', () => {
    imap.openBox('INBOX', true, (err, box) => {
      if (err) {
        imap.end();
        return res.status(500).json({ error: 'Error al abrir INBOX' });
      }
      
      imap.search(['ALL'], (err, results) => {
        if (err) {
          imap.end();
          return res.status(500).json({ error: 'Error al buscar correos' });
        }
        const page = parseInt(req.query.page) || 1;
        const perPage = parseInt(req.query.perPage) || 25;
        const total = results.length;
        const sortedResults = results.sort((a, b) => b - a); // Descendente
        const slice = sortedResults.slice((page - 1) * perPage, page * perPage);
        
        let mails = [];
        const fetch = imap.fetch(slice, { bodies: 'HEADER.FIELDS (FROM TO SUBJECT DATE)', struct: true });
        
        fetch.on('message', (msg) => {
          let mailData = {};
          msg.on('body', (stream) => {
            let buffer = '';
            stream.on('data', (chunk) => {
              buffer += chunk.toString('utf8');
            });
            stream.once('end', () => {
              mailData.header = buffer;
            });
          });
          msg.once('attributes', (attrs) => {
            mailData.attributes = attrs;
          });
          msg.once('end', () => {
            mails.push(mailData);
          });
        });
        
        fetch.once('error', (err) => {
          imap.end();
          return res.status(500).json({ error: 'Error en fetch de correos', details: err });
        });
        
        fetch.once('end', () => {
          imap.end();
          res.json({
            total,
            page,
            perPage,
            mails
          });
        });
      });
    });
  });
  
  imap.once('error', (err) => {
    return res.status(500).json({ error: 'Error en conexión IMAP', details: err });
  });
  
  imap.connect();
});

/**
 * Endpoint: POST /api/email/send
 * Requiere en los headers: x-email-user y x-email-password
 * En el body se espera un JSON con: { to, subject, text, html }
 */
app.post('/api/email/send', (req, res) => {
  const emailUser = req.headers['x-email-user'] || DEFAULT_EMAIL_USER;
  const password = req.headers['x-email-password'];
  if (!password) {
    return res.status(400).json({ error: 'Falta el header x-email-password' });
  }
  
  const { to, subject, text, html } = req.body;
  if (!to || !subject || (!text && !html)) {
    return res.status(400).json({ error: 'Faltan parámetros requeridos en el body' });
  }
  
  let transporter = nodemailer.createTransport({
    host: SMTP_HOST,
    port: SMTP_PORT,
    secure: true,
    auth: {
      user: emailUser,
      pass: password
    }
  });
  
  let mailOptions = {
    from: emailUser,
    to,
    subject,
    text,
    html
  };
  
  transporter.sendMail(mailOptions, (error, info) => {
    if (error) {
      return res.status(500).json({ error: 'Error al enviar correo', details: error });
    }
    res.json({ message: 'Correo enviado correctamente', response: info.response });
  });
});

// Inicia el servidor en el puerto definido (o 3000 por defecto)
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Microservicio de Email corriendo en el puerto ${PORT}`);
});
