// server.js
require('dotenv').config(); // Carga .env (útil en desarrollo)
const util = require('util'); // Para promisify
const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors'); // Habilitar CORS si PHP y Node están en dominios/puertos diferentes
const Imap = require('node-imap');
// const { simpleParser } = require('mailparser'); // <-- REMOVIDO/COMENTADO
const nodemailer = require('nodemailer');

const app = express();
app.use(bodyParser.json());
app.use(cors()); // Configura CORS según tus necesidades

// --- Configuración ---
const DEFAULT_EMAIL_USER = process.env.DEFAULT_EMAIL_USER || null;
const IMAP_HOST = process.env.IMAP_HOST || 'felobe.com';
const IMAP_PORT = process.env.IMAP_PORT ? parseInt(process.env.IMAP_PORT) : 993;
const IMAP_TLS = process.env.IMAP_TLS !== 'false';
const SMTP_HOST = process.env.SMTP_HOST || IMAP_HOST;
const SMTP_PORT = process.env.SMTP_PORT ? parseInt(process.env.SMTP_PORT) : 465;
const SMTP_SECURE = process.env.SMTP_SECURE !== 'false';

// --- Middleware para Autenticación Básica ---
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
        const imap = new Imap({
            user: emailUser, password: password, host: IMAP_HOST, port: IMAP_PORT, tls: IMAP_TLS,
             tlsOptions: { rejectUnauthorized: false }
        });

        imap.once('ready', () => {
            console.log(`[${emailUser}] IMAP Ready. Opening box: ${boxName}`);
            imap.openBox(boxName, false, (err, box) => { // false = read-only
                if (err) {
                    console.error(`[${emailUser}] Error opening box ${boxName}:`, err);
                    imap.end();
                    return reject({ status: 500, error: 'FOLDER_OPEN_ERROR', message: `Error al abrir carpeta ${boxName}: ${err.message}` });
                }
                console.log(`[${emailUser}] Box ${boxName} opened.`);
                resolve({ imap, box });
            });
        });

        imap.once('error', (err) => {
            console.error(`[${emailUser}] IMAP Connection Error:`, err);
            try { if (imap.state !== 'disconnected') imap.end(); } catch (e) {}
            reject({ status: 500, error: 'IMAP_CONNECTION_ERROR', message: `Error de conexión IMAP: ${err.message}` });
        });

        imap.once('end', () => {
            console.log(`[${emailUser}] IMAP Connection ended.`);
        });

        console.log(`[${emailUser}] Attempting IMAP connect...`);
        imap.connect();
    });
}

// --- Endpoints API ---

// POST /api/email/validate
app.post('/api/email/validate', requireEmailAuth, async (req, res) => {
    const { user, password } = req.emailCredentials;
    const reqLabel = `[${user}] Request /validate`; // Etiqueta para logs
    console.time(reqLabel); // Iniciar temporizador de request completo
    console.log(`${reqLabel} called.`);

    try {
        console.time(`${reqLabel} Connect`); // Iniciar temporizador de conexión
        const { imap } = await connectAndOpenBox(user, password, 'INBOX');
        console.timeEnd(`${reqLabel} Connect`); // Finalizar temporizador de conexión
        imap.end();
        console.log(`${reqLabel} Validation successful.`);
        console.timeEnd(reqLabel); // Finalizar temporizador de request completo
        res.json({ success: true, message: 'Credenciales válidas.' });
    } catch (error) {
        console.error(`${reqLabel} Validation failed:`, error);
        console.timeEnd(reqLabel); // Finalizar temporizador de request completo (en error)
        res.status(error.status || 500).json({ success: false, error: error.error || 'VALIDATION_FAILED', message: error.message || 'Error de validación IMAP.' });
    }
});


/**
 * Endpoint: GET /api/email/inbox (MODIFICADO: Sin simpleParser + CON TIMERS)
 * Obtiene mensajes paginados (cabeceras crudas y flags).
 */
app.get('/api/email/inbox', requireEmailAuth, async (req, res) => {
    const { user, password } = req.emailCredentials;
    const page = parseInt(req.query.page) || 1;
    const perPage = parseInt(req.query.perPage) || 5; // <-- Puedes cambiar este número para pruebas (ej. 5)
    const boxName = 'INBOX';
    const reqLabel = `[${user}] Request /inbox (NoParser)`; // Etiqueta para logs
    console.time(reqLabel); // <-- TIMER 1: Inicia temporizador general del request

    console.log(`${reqLabel} called. Page: ${page}, PerPage: ${perPage}`);

    let imap;
    try {
        console.time(`${reqLabel} Connect`); // <-- TIMER 2: Inicia temporizador de conexión
        const { imap: connectedImap, box } = await connectAndOpenBox(user, password, boxName);
        console.timeEnd(`${reqLabel} Connect`); // <-- TIMER 2: Termina temporizador de conexión
        imap = connectedImap;

        const totalMessages = box.messages.total;
        console.log(`[${user}] Total messages in ${boxName}: ${totalMessages}`);

        if (totalMessages === 0) {
            imap.end();
            console.timeEnd(reqLabel); // <-- TIMER 1: Termina temporizador general (caso vacío)
            return res.json({ success: true, data: { messages: [], pagination: { total: 0, currentPage: 1, totalPages: 1, perPage: perPage } } });
        }

        const totalPages = (perPage > 0) ? Math.ceil(totalMessages / perPage) : 1;
        const currentPage = Math.min(Math.max(1, page), totalPages);
        const startSeq = Math.max(1, totalMessages - (currentPage * perPage) + 1);
        const endSeq = totalMessages - ((currentPage - 1) * perPage);
        const sequenceRange = `${startSeq}:${endSeq}`;

        console.log(`[${user}] Fetching sequence range: ${sequenceRange}`);
        const fieldsToFetch = 'HEADER.FIELDS (FROM TO CC SUBJECT DATE MESSAGE-ID)';

        console.time(`${reqLabel} Fetch`); // <-- TIMER 3: Inicia temporizador del comando FETCH

        const fetchResults = imap.fetch(sequenceRange, {
            bodies: [fieldsToFetch, ''],
            // struct: true, // <-- Puedes probar comentando/cambiando a false aquí
            struct: false, // Prueba forzando a false
            markSeen: false
        });

        const processingPromises = [];

        fetchResults.on('message', (msg, seqno) => {
            const p = new Promise((resolveMsg) => {
                let rawHeaderString = '';
                let attributes = {};
                let headerStreamEnded = false;
                let attributesEnded = false;

                msg.on('body', (stream, info) => {
                    if (info.which.toUpperCase().startsWith('HEADER.FIELDS')) {
                        stream.on('data', (chunk) => { rawHeaderString += chunk.toString('utf8'); });
                        stream.once('end', () => {
                            headerStreamEnded = true;
                            if (attributesEnded) resolveMsg({ raw_headers: rawHeaderString, attributes });
                        });
                    } else {
                        stream.on('data', () => {}); // Consume stream
                        stream.once('end', () => {
                             // La lógica de resolución está en los otros 'end'
                        });
                    }
                });

                msg.once('attributes', (attrs) => {
                    attributes = attrs;
                    attributesEnded = true;
                    if (headerStreamEnded) resolveMsg({ raw_headers: rawHeaderString, attributes });
                });
            });
            processingPromises.push(p);
        });

        fetchResults.once('error', (err) => {
            console.error(`${reqLabel} IMAP Fetch Error:`, err);
            console.timeEnd(`${reqLabel} Fetch`); // <-- TIMER 3: Termina temporizador FETCH (en error)
            try { if (imap.state !== 'disconnected') imap.end(); } catch (e) {}
             // Usar reject para que el catch externo lo maneje
            reject({ status: 500, error: 'IMAP_FETCH_ERROR', message: `Error al obtener mensajes: ${err.message}` });
        });

        fetchResults.once('end', async () => {
            console.timeEnd(`${reqLabel} Fetch`); // <-- TIMER 3: Termina temporizador FETCH (éxito)
            console.log(`${reqLabel} IMAP Fetch completed.`);

            try {
                console.time(`${reqLabel} Processing`); // <-- TIMER 4: Inicia temporizador del procesamiento post-fetch
                const rawMessagesData = await Promise.all(processingPromises);
                console.log(`[${user}] Message processing completed. Count: ${rawMessagesData.length}`);

                const finalMessages = rawMessagesData.map(data => {
                    const attrs = data.attributes || {};
                    const raw_headers = data.raw_headers || '';
                    // const hasAttachments = attrs.struct ? attrs.struct.some(...) : false; // Original con struct: true
                    const hasAttachments = false; // Forzado a false porque struct está en false

                    return {
                        uid: attrs.uid,
                        raw_headers: raw_headers,
                        subject: '', from_address: '', from_name: '', // PHP los parseará
                        date: attrs.date ? (new Date(attrs.date)).toLocaleString('es-MX', { timeZone: 'America/Mexico_City' }) : '?',
                        is_seen: attrs.flags ? attrs.flags.includes('\\Seen') : false,
                        has_attachments: hasAttachments,
                        flags: attrs.flags || []
                    };
                }).reverse();

                console.log(`[${user}] Data prepared for JSON response (raw headers).`);
                console.timeEnd(`${reqLabel} Processing`); // <-- TIMER 4: Termina temporizador del procesamiento
                imap.end();
                console.timeEnd(reqLabel); // <-- TIMER 1: Termina temporizador general (éxito)
                res.json({
                    success: true,
                    data: { messages: finalMessages, pagination: { total: totalMessages, currentPage: currentPage, totalPages: totalPages, perPage: perPage } }
                });
            } catch (processingError) {
                console.error(`${reqLabel} Error processing messages after fetch:`, processingError);
                console.timeEnd(`${reqLabel} Processing`); // <-- TIMER 4: Termina temporizador del procesamiento (en error)
                 try { if (imap.state !== 'disconnected') imap.end(); } catch (e) {}
                console.timeEnd(reqLabel); // <-- TIMER 1: Termina temporizador general (en error de procesamiento)
                res.status(500).json({ success: false, error: 'PROCESSING_ERROR', message: 'Error interno al procesar mensajes.' });
            }
        });

    } catch (error) {
        console.error(`${reqLabel} Error general en /inbox:`, error);
        // Asegurarse de cerrar IMAP y parar timers si aún corren
        try { if (imap && imap.state !== 'disconnected') imap.end(); } catch (e) {}
        console.timeEnd(reqLabel); // <-- TIMER 1: Termina temporizador general (en catch principal)
        // Podrías intentar parar los otros timers aquí también, pero puede ser complejo saber cuáles iniciaron
        res.status(error.status || 500).json({ success: false, error: error.error || 'UNKNOWN_ERROR', message: error.message || 'Error desconocido.' });
    }
});

// POST /api/email/send
app.post('/api/email/send', requireEmailAuth, async (req, res) => {
    // ... (Código de envío sin cambios significativos, puedes añadir timers si quieres) ...
    const { user, password } = req.emailCredentials;
    const { to, subject, text, html, cc, bcc } = req.body;
    console.log(`[${user}] Endpoint /send called. To: ${to}`);
    // ... (Validaciones) ...
    if (!to || !subject || (!text && !html)) return res.status(400).json({ success: false, error: 'MISSING_PARAMS', message: 'Faltan parámetros requeridos.' });
    let transporter = nodemailer.createTransport({ host: SMTP_HOST, port: SMTP_PORT, secure: SMTP_SECURE, auth: { user: user, pass: password }, tls: { rejectUnauthorized: false } });
    let mailOptions = { from: `"${req.body.fromName || user}" <${user}>`, to: to, subject: subject, text: text, html: html };
    if (cc) mailOptions.cc = cc; if (bcc) mailOptions.bcc = bcc;
    try {
        let info = await transporter.sendMail(mailOptions);
        res.json({ success: true, message: 'Correo enviado.', messageId: info.messageId });
    } catch (error) {
        // ... (Manejo de errores de envío) ...
        res.status(500).json({ success: false, error: 'SEND_FAILED', message: 'Error al enviar.' });
    }
});


// --- Endpoints Adicionales (PENDIENTES) ---
app.get('/api/email/message/:uid', requireEmailAuth, async (req, res) => { res.status(501).json({ success: false, error: 'NOT_IMPLEMENTED' }); });
app.delete('/api/email/message/:uid', requireEmailAuth, async (req, res) => { res.status(501).json({ success: false, error: 'NOT_IMPLEMENTED' }); });
app.post('/api/email/message/:uid/flags', requireEmailAuth, async (req, res) => { res.status(501).json({ success: false, error: 'NOT_IMPLEMENTED' }); });
app.get('/api/email/attachment/:uid/:attachmentFilename', requireEmailAuth, async (req, res) => { res.status(501).json({ success: false, error: 'NOT_IMPLEMENTED' }); });
app.get('/api/email/folders', requireEmailAuth, async (req, res) => { res.status(501).json({ success: false, error: 'NOT_IMPLEMENTED' }); });


// --- Iniciar Servidor ---
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Microservicio Email (NoParser + Timers) corriendo en http://localhost:${PORT}`);
});