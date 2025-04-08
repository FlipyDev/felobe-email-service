// server.js
require('dotenv').config();
const util = require('util');
const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const Imap = require('node-imap');
const nodemailer = require('nodemailer');
// const iconv = require('iconv-lite'); // Descomentar si se instala y usa

const app = express();
app.use(bodyParser.json());
app.use(cors());

// --- Configuración ---
const DEFAULT_EMAIL_USER = process.env.DEFAULT_EMAIL_USER || null;
const IMAP_HOST = process.env.IMAP_HOST || 'felobe.com';
const IMAP_PORT = process.env.IMAP_PORT ? parseInt(process.env.IMAP_PORT) : 993;
const IMAP_TLS = process.env.IMAP_TLS !== 'false';
const SMTP_HOST = process.env.SMTP_HOST || IMAP_HOST;
const SMTP_PORT = process.env.SMTP_PORT ? parseInt(process.env.SMTP_PORT) : 465;
const SMTP_SECURE = process.env.SMTP_SECURE !== 'false';

// --- Middleware ---
const requireEmailAuth = (req, res, next) => {
    const emailUser = req.headers['x-email-user'];
    const password = req.headers['x-email-password'];
    if (!emailUser || !password) {
        console.error(`[${new Date().toISOString()}] Auth Error: Missing x-email-user or x-email-password headers.`);
        return res.status(401).json({ success: false, error: 'AUTH_REQUIRED', message: 'Faltan credenciales de correo en la cabecera.' });
    }
    req.emailCredentials = { user: emailUser, password: password };
    console.log(`[${new Date().toISOString()}] Auth Check OK for user: ${emailUser}`);
    next();
};

// --- Funciones Helper IMAP ---
function connectAndOpenBox(emailUser, password, boxName = 'INBOX') {
    return new Promise((resolve, reject) => {
        const imap = new Imap({ user: emailUser, password: password, host: IMAP_HOST, port: IMAP_PORT, tls: IMAP_TLS, tlsOptions: { rejectUnauthorized: false } });
        imap.once('ready', () => {
            // console.log(`[${emailUser}] IMAP Ready. Opening box: ${boxName}`); // Log menos verboso
            imap.openBox(boxName, false, (err, box) => {
                if (err) {
                    console.error(`[${emailUser}] Error opening box ${boxName}:`, err.message);
                    try { imap.end(); } catch(e){}
                    return reject({ status: 500, error: 'FOLDER_OPEN_ERROR', message: `Error al abrir carpeta ${boxName}: ${err.message}` });
                }
                // console.log(`[${emailUser}] Box ${boxName} opened.`); // Log menos verboso
                resolve({ imap, box });
            });
        });
        imap.once('error', (err) => {
             console.error(`[${emailUser}] IMAP Connection Error:`, err);
             try { if (imap.state !== 'disconnected') imap.end(); } catch (e) {}
             reject({ status: 500, error: 'IMAP_CONNECTION_ERROR', message: `Error de conexión IMAP: ${err.message}` });
         });
        imap.once('end', () => { console.log(`[${emailUser}] IMAP Connection ended.`); });
        // console.log(`[${emailUser}] Attempting IMAP connect...`); // Log menos verboso
        imap.connect();
    });
}

// --- Función de Parsing Manual Básico (con try-catch) ---
function parseBasicHeadersManually(rawHeaderString) {
    const headers = { subject: '(Sin Asunto)', from: '?' };
    if (!rawHeaderString) return headers;

    try { // Envolver todo en try-catch general
        const lines = rawHeaderString.split(/\r?\n/);
        let currentHeader = '';
        let currentValue = '';

        const decodeRFC2047 = (str) => {
            // Usar try-catch dentro del replace para aislar errores de decodificación
            return str.replace(/=\?([^?]+)\?(B|Q)\?([^?]+)\?=/gi, (match, charset, encoding, encodedText) => {
                try {
                    charset = charset.toUpperCase();
                    encoding = encoding.toUpperCase();
                    if (encoding === 'B') {
                        const buffer = Buffer.from(encodedText, 'base64');
                        // if (iconv.encodingExists(charset) && charset !== 'UTF-8') { return iconv.decode(buffer, charset); }
                        return buffer.toString('utf-8');
                    } else if (encoding === 'Q') {
                        let decodedQ = encodedText.replace(/_/g, ' ').replace(/=([A-F0-9]{2})/gi, (m, hex) => String.fromCharCode(parseInt(hex, 16)));
                        const buffer = Buffer.from(decodedQ, 'latin1');
                        // if (iconv.encodingExists(charset) && charset !== 'UTF-8') { return iconv.decode(buffer, charset); }
                        return buffer.toString('utf-8');
                    }
                } catch (e) {
                    console.warn("Error decoding header part:", match, e.message);
                    return match; // Devolver original si falla
                }
                return match;
            });
        };

        for (const line of lines) {
            if (line.match(/^[A-Za-z-]+:/)) {
                if (currentHeader && currentValue) {
                    if (currentHeader === 'subject') headers.subject = decodeRFC2047(currentValue.trim());
                    else if (currentHeader === 'from') headers.from = decodeRFC2047(currentValue.trim());
                }
                const parts = line.split(':', 2);
                currentHeader = parts[0].toLowerCase().trim();
                currentValue = parts[1] || '';
            } else if (line.match(/^\s+/) && currentValue) {
                currentValue += ' ' + line.trim();
            } else {
                if (currentHeader && currentValue) {
                     if (currentHeader === 'subject') headers.subject = decodeRFC2047(currentValue.trim());
                     else if (currentHeader === 'from') headers.from = decodeRFC2047(currentValue.trim());
                }
                currentHeader = ''; currentValue = '';
            }
        }
        if (currentHeader && currentValue) {
             if (currentHeader === 'subject') headers.subject = decodeRFC2047(currentValue.trim());
             else if (currentHeader === 'from') headers.from = decodeRFC2047(currentValue.trim());
        }
    } catch (parseError) {
        console.error("Error during manual header parsing:", parseError);
        // Devolver valores por defecto si falla el parsing general
        return { subject: '(Error Parsing Subject)', from: '(Error Parsing From)' };
    }
    return headers;
}

// --- Endpoints API ---

// POST /api/email/validate
app.post('/api/email/validate', requireEmailAuth, async (req, res) => {
    const { user, password } = req.emailCredentials;
    const reqLabel = `[${user}] Request /validate`;
    console.time(reqLabel);
    console.log(`${reqLabel} called.`);
    try {
        console.time(`${reqLabel} Connect`);
        const { imap } = await connectAndOpenBox(user, password, 'INBOX');
        console.timeEnd(`${reqLabel} Connect`);
        imap.end();
        console.log(`${reqLabel} Validation successful.`);
        console.timeEnd(reqLabel);
        res.json({ success: true, message: 'Credenciales válidas.' });
    } catch (error) {
        console.error(`${reqLabel} Validation failed:`, error);
        console.timeEnd(reqLabel);
        res.status(error.status || 500).json({ success: false, error: error.error || 'VALIDATION_FAILED', message: error.message || 'Error de validación IMAP.' });
    }
});

// GET /api/email/inbox
app.get('/api/email/inbox', requireEmailAuth, async (req, res) => {
    const { user, password } = req.emailCredentials;
    const page = parseInt(req.query.page) || 1;
    const perPage = parseInt(req.query.perPage) || 5;
    const boxName = 'INBOX';
    const reqLabel = `[${user}] Request /inbox (ManualParser)`;
    console.time(reqLabel);
    console.log(`${reqLabel} called. Page: ${page}, PerPage: ${perPage}`);

    let imap;
    try {
        console.time(`${reqLabel} Connect`);
        const { imap: connectedImap, box } = await connectAndOpenBox(user, password, boxName);
        console.timeEnd(`${reqLabel} Connect`);
        imap = connectedImap;

        const totalMessages = box.messages.total;
        console.log(`[${user}] Total messages in ${boxName}: ${totalMessages}`);

        if (totalMessages === 0) {
            imap.end(); console.timeEnd(reqLabel);
            return res.json({ success: true, data: { messages: [], pagination: { total: 0, currentPage: 1, totalPages: 1, perPage: perPage } } });
        }

        const totalPages = Math.ceil(totalMessages / perPage);
        const currentPage = Math.min(Math.max(1, page), totalPages);
        const startSeq = Math.max(1, totalMessages - (currentPage * perPage) + 1);
        const endSeq = totalMessages - ((currentPage - 1) * perPage);
        const sequenceRange = `${startSeq}:${endSeq}`;
        console.log(`[${user}] Fetching sequence range: ${sequenceRange}`);
        const fieldsToFetch = 'HEADER.FIELDS (FROM SUBJECT DATE)';

        console.time(`${reqLabel} Fetch`);
        const fetchResults = imap.fetch(sequenceRange, { bodies: [fieldsToFetch, ''], struct: false, markSeen: false });
        const processingPromises = []; // Array para guardar las promesas de cada mensaje

        fetchResults.on('message', (msg, seqno) => {
            // Crear una promesa para el procesamiento de este mensaje específico
            const messagePromise = new Promise((resolveMsg, rejectMsg) => { // Añadir rejectMsg
                let rawHeaderString = '';
                let attributes = {};
                let headerStreamEnded = false;
                let attributesReceived = false; // Renombrado para claridad

                 // Timeout por mensaje por si algo se queda colgado (ej. 10 segundos)
                const messageTimeout = setTimeout(() => {
                    console.error(`[${user}] Timeout processing message seq ${seqno}`);
                    // Rechazar la promesa específica de este mensaje
                    rejectMsg(new Error(`Timeout processing message seq ${seqno}`));
                }, 10000); // 10 segundos

                msg.on('body', (stream, info) => {
                     if (info.which.toUpperCase().startsWith('HEADER.FIELDS')) {
                        stream.on('data', (chunk) => { rawHeaderString += chunk.toString('utf8'); });
                        stream.once('end', () => {
                            headerStreamEnded = true;
                            if (attributesReceived) {
                                clearTimeout(messageTimeout); // Cancelar timeout
                                resolveMsg({ raw_headers: rawHeaderString, attributes });
                            }
                        });
                        // Manejar error del stream de body
                        stream.once('error', (streamErr) => {
                             console.error(`[${user}] Error in body stream for seq ${seqno}:`, streamErr);
                             clearTimeout(messageTimeout);
                             rejectMsg(new Error(`Stream error for seq ${seqno}: ${streamErr.message}`));
                        });
                    } else {
                        stream.on('data', () => {}); // Consumir otros streams
                        stream.once('end', () => {}); // Ignorar fin de otros streams
                    }
                });

                msg.once('attributes', (attrs) => {
                    attributes = attrs;
                    attributesReceived = true;
                    if (headerStreamEnded) {
                         clearTimeout(messageTimeout); // Cancelar timeout
                         resolveMsg({ raw_headers: rawHeaderString, attributes });
                    }
                });

                // Manejar error general del mensaje
                 msg.once('error', (msgErr) => {
                      console.error(`[${user}] Error event for message seq ${seqno}:`, msgErr);
                      clearTimeout(messageTimeout);
                      rejectMsg(new Error(`Message error for seq ${seqno}: ${msgErr.message}`));
                 });

                // msg.once('end') no es fiable para saber si todo terminó, usar flags

            }); // Fin de new Promise
            processingPromises.push(messagePromise); // Añadir promesa al array
        }); // Fin fetchResults.on('message')

        fetchResults.once('error', (err) => {
            console.error(`${reqLabel} IMAP Fetch Error:`, err);
            console.timeEnd(`${reqLabel} Fetch`);
            try { if (imap.state !== 'disconnected') imap.end(); } catch (e) {}
            // Rechazar la promesa global (o manejar error directamente)
            // Esta parte es más compleja de integrar con las promesas individuales,
            // por ahora, simplemente devolvemos error general.
            // Para un manejo perfecto, se necesitaría Promise.allSettled y filtrar resultados.
             if (!res.headersSent) { // Evitar enviar respuesta dos veces
                 res.status(500).json({ success: false, error: 'IMAP_FETCH_ERROR', message: `Error al obtener mensajes: ${err.message}` });
             }
             // Tendríamos que cancelar las promesas pendientes si es posible
        });

        fetchResults.once('end', async () => {
            console.timeEnd(`${reqLabel} Fetch`);
            console.log(`${reqLabel} IMAP Fetch completed. Waiting for message processing...`);

            try {
                console.time(`${reqLabel} Processing`);
                // Usar Promise.allSettled para manejar errores individuales sin detener todo
                const results = await Promise.allSettled(processingPromises);
                console.log(`[${user}] Individual message processing settled. Results count: ${results.length}`);

                const finalMessages = [];
                results.forEach((result, index) => {
                    if (result.status === 'fulfilled') {
                        const data = result.value; // El objeto { raw_headers, attributes }
                        const attrs = data.attributes || {};
                        const raw_headers = data.raw_headers || '';
                        const parsedHeaders = parseBasicHeadersManually(raw_headers); // Parsear
                        const hasAttachments = false; // Forzado

                        finalMessages.push({
                            uid: attrs.uid,
                            subject: parsedHeaders.subject,
                            from_address: '', // Placeholder
                            from_name: parsedHeaders.from,
                            date: attrs.date ? (new Date(attrs.date)).toLocaleString('es-MX', { timeZone: 'America/Mexico_City' }) : '?',
                            is_seen: attrs.flags ? attrs.flags.includes('\\Seen') : false,
                            has_attachments: hasAttachments,
                            flags: attrs.flags || []
                        });
                    } else {
                        // Error procesando un mensaje específico
                        console.error(`[${user}] Failed to process message at index ${index}:`, result.reason.message);
                        // Podrías añadir un placeholder o simplemente omitir el mensaje con error
                        // finalMessages.push({ uid: null, subject: 'Error Processing Message', ... });
                    }
                });

                // Invertir el array de mensajes procesados correctamente
                 finalMessages.reverse();

                console.log(`[${user}] Manual parsing and data prep completed. Final messages count: ${finalMessages.length}`);
                console.timeEnd(`${reqLabel} Processing`);
                imap.end();
                console.timeEnd(reqLabel);
                 if (!res.headersSent) {
                    res.json({
                        success: true,
                        data: { messages: finalMessages, pagination: { total: totalMessages, currentPage: currentPage, totalPages: totalPages, perPage: perPage } }
                    });
                 }
            } catch (processingError) { // Error en Promise.allSettled o mapeo (poco probable)
                console.error(`${reqLabel} Error processing messages after fetch:`, processingError);
                console.timeEnd(`${reqLabel} Processing`);
                try { if (imap.state !== 'disconnected') imap.end(); } catch (e) {}
                console.timeEnd(reqLabel);
                 if (!res.headersSent) {
                    res.status(500).json({ success: false, error: 'PROCESSING_ERROR', message: 'Error interno al procesar mensajes.' });
                 }
            }
        }); // Fin fetchResults.once('end')

    } catch (error) { // Error en connectAndOpenBox o antes del fetch
        console.error(`${reqLabel} Error general en /inbox:`, error);
        try { if (imap && imap.state !== 'disconnected') imap.end(); } catch (e) {}
        console.timeEnd(reqLabel);
         if (!res.headersSent) {
            res.status(error.status || 500).json({ success: false, error: error.error || 'UNKNOWN_ERROR', message: error.message || 'Error desconocido.' });
         }
    }
});

// POST /api/email/send
app.post('/api/email/send', requireEmailAuth, async (req, res) => {
    const { user, password } = req.emailCredentials;
    const { to, subject, text, html, cc, bcc } = req.body;
    const reqLabel = `[${user}] Request /send`;
    console.log(`${reqLabel} called. To: ${to}`);

    if (!to || !subject || (!text && !html)) {
        return res.status(400).json({ success: false, error: 'MISSING_PARAMS', message: 'Faltan parámetros requeridos.' });
    }
    // Simple email validation (adjust regex if needed)
    const validateEmails = (emails) => { if (!emails) return true; return emails.split(',').every(email => /\S+@\S+\.\S+/.test(email.trim())); };
    if (!validateEmails(to) || !validateEmails(cc) || !validateEmails(bcc)) {
         return res.status(400).json({ success: false, error: 'INVALID_RECIPIENT', message: 'Una o más direcciones de correo son inválidas.' });
    }

    let transporter = nodemailer.createTransport({ host: SMTP_HOST, port: SMTP_PORT, secure: SMTP_SECURE, auth: { user: user, pass: password }, tls: { rejectUnauthorized: false } });
    let mailOptions = { from: `"${req.body.fromName || user}" <${user}>`, to: to, subject: subject, text: text, html: html };
    if (cc) mailOptions.cc = cc; if (bcc) mailOptions.bcc = bcc;

    try {
        console.time(`${reqLabel} SMTP Send`);
        let info = await transporter.sendMail(mailOptions);
        console.timeEnd(`${reqLabel} SMTP Send`);
        console.log(`${reqLabel} Correo enviado OK. Message ID: ${info.messageId}`);
        res.json({ success: true, message: 'Correo enviado correctamente.', messageId: info.messageId });
    } catch (error) {
        console.timeEnd(`${reqLabel} SMTP Send`); // Stop timer on error too
        console.error(`${reqLabel} Error al enviar correo SMTP:`, error);
        let errorCode = 'SEND_FAILED', errorMsg = 'Error al enviar el correo.';
        if (error.code === 'EAUTH' || error.responseCode === 535) { errorCode = 'AUTH_FAILED'; errorMsg = 'Fallo de autenticación SMTP.'; }
        else if (error.code === 'EENVELOPE' || [550, 551, 553, 554].includes(error.responseCode)) { errorCode = 'INVALID_RECIPIENT'; errorMsg = 'Dirección de destinatario rechazada.'; }
        res.status(500).json({ success: false, error: errorCode, message: errorMsg, details: error.message });
    }
});


// --- Endpoints Adicionales (PENDIENTES) ---
app.get('/api/email/message/:uid', requireEmailAuth, async (req, res) => { res.status(501).json({ success: false, error: 'NOT_IMPLEMENTED', message: 'Detalle no implementado.' }); });
app.delete('/api/email/message/:uid', requireEmailAuth, async (req, res) => { res.status(501).json({ success: false, error: 'NOT_IMPLEMENTED', message: 'Eliminación no implementada.' }); });
app.post('/api/email/message/:uid/flags', requireEmailAuth, async (req, res) => { res.status(501).json({ success: false, error: 'NOT_IMPLEMENTED', message: 'Flags no implementado.' }); });
app.get('/api/email/attachment/:uid/:attachmentFilename', requireEmailAuth, async (req, res) => { res.status(501).json({ success: false, error: 'NOT_IMPLEMENTED', message: 'Adjuntos no implementado.' }); });
app.get('/api/email/folders', requireEmailAuth, async (req, res) => { res.status(501).json({ success: false, error: 'NOT_IMPLEMENTED', message: 'Carpetas no implementado.' }); });


// --- Iniciar Servidor ---
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Microservicio Email (ManualParser + Timers + ErrHandling) corriendo en http://localhost:${PORT}`);
});