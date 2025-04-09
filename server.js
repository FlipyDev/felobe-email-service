// server.js (Versión Única y Completa v3)
require('dotenv').config();
const util = require('util');
const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const Imap = require('node-imap');
const nodemailer = require('nodemailer');
const { simpleParser } = require('mailparser');
const { PassThrough } = require('stream');

const app = express();
app.use(bodyParser.json({ limit: '25mb' }));
app.use(bodyParser.urlencoded({ limit: '25mb', extended: true }));
app.use(cors());

// --- Configuración ---
const IMAP_HOST = process.env.IMAP_HOST || 'felobe.com';
const IMAP_PORT = process.env.IMAP_PORT ? parseInt(process.env.IMAP_PORT) : 993;
const IMAP_TLS = process.env.IMAP_TLS !== 'false';
const SMTP_HOST = process.env.SMTP_HOST || IMAP_HOST;
const SMTP_PORT = process.env.SMTP_PORT ? parseInt(process.env.SMTP_PORT) : 465;
const SMTP_SECURE = process.env.SMTP_SECURE !== 'false';

// --- Middleware de Autenticación ---
const requireEmailAuth = (req, res, next) => {
    const emailUser = req.headers['x-email-user']; const password = req.headers['x-email-password'];
    if (!emailUser || !password) { console.error(`Auth Error: Missing headers.`); return res.status(401).json({ success: false, error: 'AUTH_REQUIRED', message: 'Faltan credenciales.' }); }
    req.emailCredentials = { user: emailUser, password: password }; next();
};

// --- Funciones Helper IMAP ---
function connectAndOpenBox(emailUser, password, boxName = 'INBOX', readOnly = true) {
    const reqLabel = `[${emailUser}]`; // Etiqueta para logs

    // --- AJUSTE: Determinar el nombre IMAP real con prefijo si es necesario ---
    let adjustedBoxName = ''; // Nombre que se pasará a imap.openBox
    if (boxName === '') {
        // Si se pide conectar sin abrir (para listar carpetas), no ajustamos nombre.
        adjustedBoxName = '';
    } else if (boxName.toUpperCase() === 'INBOX') {
        // Si es INBOX, usar INBOX directamente.
        adjustedBoxName = 'INBOX';
    } else {
        // Para otras carpetas, asumir prefijo INBOX. (Ajusta si tu servidor usa otro prefijo)
        adjustedBoxName = `INBOX.${boxName}`;
    }
    // -----------------------------------------------------------------------

    return new Promise((resolve, reject) => {
        const imap = new Imap({
            user: emailUser, // Usar argumento de la función
            password: password, // Usar argumento de la función
            host: IMAP_HOST,
            port: IMAP_PORT,
            tls: IMAP_TLS,
            tlsOptions: { rejectUnauthorized: false } // ¡CUIDADO! Menos seguro, solo si hay problemas de certificado SSL.
            // debug: (msg) => { console.log(`${reqLabel} IMAP Debug: ${msg}`); } // Descomentar para debug IMAP muy detallado
        });

        // Timeout para la conexión inicial
        const connectionTimeout = setTimeout(() => {
            reject({ status: 504, error: 'IMAP_TIMEOUT', message: 'Timeout conectando al servidor IMAP.' });
            try {
                imap.destroy(); // Intentar destruir conexión en timeout
            } catch(e){
                // Ignorar errores al destruir
            }
        }, 20000); // 20 segundos de timeout para conectar

        // Evento 'ready': Conexión establecida con éxito
        imap.once('ready', () => {
            clearTimeout(connectionTimeout); // Cancelar timeout de conexión

            // Si se pidió conectar sin abrir una caja (ej. para listar carpetas)
            if (adjustedBoxName === '') {
                console.log(`${reqLabel} IMAP Ready (no box opened).`);
                resolve({ imap: imap, box: null }); // Devolver imap conectado, box es null
                return; // Salir de la función 'ready'
            }

            // Si se pidió abrir una caja específica
            console.log(`${reqLabel} IMAP Ready. Opening adjusted box: ${adjustedBoxName} (ReadOnly: ${readOnly})`);
            imap.openBox(adjustedBoxName, readOnly, (err, box) => {
                if (err) {
                    // Error al abrir la caja (puede ser por nombre incorrecto, permisos, etc.)
                    console.error(`${reqLabel} Error opening box ${adjustedBoxName}:`, err.message);
                    try {
                        imap.end(); // Intentar cerrar conexión limpiamente
                    } catch(e){}
                    // Rechazar la promesa con detalles del error
                    return reject({ status: 500, error: 'FOLDER_OPEN_ERROR', message: `Error al abrir carpeta '${adjustedBoxName}': ${err.message}` });
                }
                // Caja abierta con éxito
                console.log(`${reqLabel} Box ${adjustedBoxName} opened successfully.`);
                resolve({ imap: imap, box: box }); // Devolver imap y la caja abierta
            });
        });

        // Evento 'error': Error general de la conexión IMAP
        imap.once('error', (err) => {
             clearTimeout(connectionTimeout); // Cancelar timeout si aún estaba activo
             console.error(`${reqLabel} IMAP Connection Error:`, err);
             try {
                 // Intentar cerrar la conexión si no está ya desconectada
                 if (imap.state !== 'disconnected') imap.end();
             } catch (e) {}
             // Clasificar error común de autenticación
             let errorCode = 'IMAP_CONNECTION_ERROR';
             let errorMsg = `Error de conexión IMAP: ${err.message}`;
             let status = 500; // Error interno del servidor por defecto
             if (err.message && (err.message.toLowerCase().includes('invalid credentials') || err.message.toLowerCase().includes('authentication failed'))) {
                errorCode = 'AUTH_FAILED';
                errorMsg = 'Credenciales IMAP inválidas.';
                status = 401; // Unauthorized
             }
             // Rechazar la promesa
             reject({ status: status, error: errorCode, message: errorMsg });
         });

        // Evento 'end': La conexión se cerró (normalmente después de llamar a imap.end())
        imap.once('end', () => {
            // console.log(`${reqLabel} IMAP Connection ended.`); // Log opcional
        });

        // Iniciar la conexión
        try {
            // console.log(`${reqLabel} Attempting IMAP connect...`); // Log opcional
            imap.connect();
        } catch (connectErr) {
             // Capturar excepción síncrona si imap.connect falla inmediatamente
             clearTimeout(connectionTimeout);
             console.error(`${reqLabel} IMAP Initial Connect Exception:`, connectErr);
             reject({ status: 500, error: 'IMAP_CONNECT_EXCEPTION', message: `Excepción al iniciar conexión: ${connectErr.message}` });
        }
    }); // Fin de new Promise
}
function parseCompleteMessage(stream) {
    return new Promise((resolve, reject) => { simpleParser(stream, { skipHtmlToText: true, skipTextToHtml: true }, (err, mail) => err ? reject(new Error(`Mailparser failed: ${err.message}`)) : resolve(mail)); });
}

// --- Función de Parsing Manual Básico (CORREGIDA OTRA VEZ) ---
/**
 * Parsea Subject, From y To de un string de cabeceras crudo.
 * Maneja decodificación simple RFC 2047 (Base64/UTF-8).
 * @param {string} rawHeaderString
 * @returns {{subject: string, from: string, to: string}}
 */
function parseBasicHeadersManually(rawHeaderString) {
    const headers = { subject: '(Sin Asunto)', from: '?', to: '?' }; // Inicializa con 'to'
    if (!rawHeaderString) return headers;

    try {
        const lines = rawHeaderString.split(/\r?\n/);
        let currentHeader = '';
        let currentValue = '';

        const decodeRFC2047 = (str) => {
            return str.replace(/=\?([^?]+)\?(B|Q)\?([^?]+)\?=/gi, (match, charset, encoding, encodedText) => {
                try {
                    charset = charset.toUpperCase();
                    encoding = encoding.toUpperCase();
                    if (encoding === 'B') {
                        return Buffer.from(encodedText, 'base64').toString('utf-8');
                    } else if (encoding === 'Q') {
                        let decodedQ = encodedText.replace(/_/g, ' ').replace(/=([A-F0-9]{2})/gi, (m, hex) => String.fromCharCode(parseInt(hex, 16)));
                        return Buffer.from(decodedQ, 'latin1').toString('utf-8');
                    }
                } catch (e) {
                    console.warn("Decode err:", match, e.message);
                }
                return match;
            });
        };

        for (const line of lines) {
            // Detecta inicio de nueva cabecera
            if (line.match(/^[A-Za-z-]+:/)) {
                // Procesa valor acumulado de cabecera anterior
                if (currentHeader && currentValue) { // Correcto: && currentValue
                    if (currentHeader === 'subject') headers.subject = decodeRFC2047(currentValue.trim());
                    else if (currentHeader === 'from') headers.from = decodeRFC2047(currentValue.trim());
                    else if (currentHeader === 'to') headers.to = decodeRFC2047(currentValue.trim()); // Añadido TO
                }
                // Inicia nueva cabecera
                const parts = line.split(':', 2);
                currentHeader = parts[0].toLowerCase().trim();
                currentValue = parts[1] || '';
            }
            // Detecta continuación de cabecera
            else if (line.match(/^\s+/) && currentValue) { // Correcto: && currentValue
                currentValue += ' ' + line.trim();
            }
             // Línea vacía o inválida, procesar última cabecera acumulada
            else {
                 if (currentHeader && currentValue) { // Correcto: && currentValue
                     if (currentHeader === 'subject') headers.subject = decodeRFC2047(currentValue.trim());
                     else if (currentHeader === 'from') headers.from = decodeRFC2047(currentValue.trim());
                     else if (currentHeader === 'to') headers.to = decodeRFC2047(currentValue.trim()); // Añadido TO
                 }
                // Resetear para la siguiente línea (o fin)
                currentHeader = '';
                currentValue = '';
            }
        }
         // Procesar la última cabecera si quedó algo al final
         if (currentHeader && currentValue) { // Correcto: && currentValue
             if (currentHeader === 'subject') headers.subject = decodeRFC2047(currentValue.trim());
             else if (currentHeader === 'from') headers.from = decodeRFC2047(currentValue.trim());
             else if (currentHeader === 'to') headers.to = decodeRFC2047(currentValue.trim()); // Añadido TO
         }
    } catch (parseError) {
        console.error("Error during manual header parsing:", parseError);
        return { subject: '(Error Parse)', from: '(Error Parse)', to: '(Error Parse)' };
    }
    return headers;
}

// --- Endpoints API ---

// POST /api/email/validate
app.post('/api/email/validate', requireEmailAuth, async (req, res) => {
    const { user, password } = req.emailCredentials; const reqLabel = `[${user}] POST /validate`; console.time(reqLabel); console.log(reqLabel); let imap;
    try { const conn = await connectAndOpenBox(user, password, 'INBOX', true); imap = conn.imap; imap.end(); console.log(`${reqLabel} OK`); console.timeEnd(reqLabel); res.json({ success: true, message: 'Credenciales válidas.' }); }
    catch (error) { console.error(`${reqLabel} FAILED:`, error); console.timeEnd(reqLabel); res.status(error.status || 500).json({ success: false, error: error.error || 'VALIDATION_FAILED', message: error.message || 'Error validación IMAP.' }); }
});

// GET /api/email/inbox
app.get('/api/email/inbox', requireEmailAuth, async (req, res) => {
    const { user, password } = req.emailCredentials; const boxName = 'INBOX'; const page = parseInt(req.query.page) || 1; const perPage = parseInt(req.query.perPage) || 15; const reqLabel = `[${user}] GET /inbox p${page}`; console.time(reqLabel); console.log(reqLabel); let imap;
    try {
        console.time(`${reqLabel} Connect`); const { imap: connectedImap, box } = await connectAndOpenBox(user, password, boxName, true); console.timeEnd(`${reqLabel} Connect`); imap = connectedImap;
        const totalMessages = box.messages.total; if (totalMessages === 0) { imap.end(); console.timeEnd(reqLabel); return res.json({ success: true, data: { messages: [], pagination: { total: 0, currentPage: 1, totalPages: 1, perPage: perPage } } }); }
        const totalPages = Math.ceil(totalMessages / perPage); const currentPage = Math.min(Math.max(1, page), totalPages); const startSeq = Math.max(1, totalMessages - ((currentPage - 1) * perPage)); const endSeq = Math.max(1, startSeq - perPage + 1); const sequenceRange = `${endSeq}:${startSeq}`; console.log(`${reqLabel} Total:${totalMessages} Fetch:${sequenceRange}`); const fieldsToFetch = 'HEADER.FIELDS (FROM SUBJECT DATE)'; // Solo From/Subject/Date para lista inbox
        console.time(`${reqLabel} Fetch`); const fetchResults = imap.fetch(sequenceRange, { bodies: [fieldsToFetch, ''], struct: true, markSeen: false }); const processingPromises = [];
        fetchResults.on('message', (msg, seqno) => { const p = new Promise((resolveMsg, rejectMsg) => { let h='', a={}, hs=false, ar=false; const t=setTimeout(()=>rejectMsg(new Error(`Timeout seq ${seqno}`)),15000); msg.on('body',(s,i)=>{ if(i.which.toUpperCase().startsWith('H')){ s.on('data',c=>h+=c.toString('utf8')); s.once('end',()=>{hs=true;if(ar){clearTimeout(t);resolveMsg({h,a});}}); s.once('error',e=>{clearTimeout(t);rejectMsg(new Error(`Stream err ${seqno}:${e.message}`));});} else {s.on('data',()=>{});s.once('end',()=>{});}}); msg.once('attributes',at=>{a=at;ar=true;if(hs){clearTimeout(t);resolveMsg({h,a});}}); msg.once('error',e=>{clearTimeout(t);rejectMsg(new Error(`Msg err ${seqno}:${e.message}`));}); }); processingPromises.push(p); });
        fetchResults.once('error', (err) => { console.error(`${reqLabel} Fetch Error:`, err); throw new Error(err.message); }); // Lanzar error para catch general
        fetchResults.once('end', async () => {
            console.timeEnd(`${reqLabel} Fetch`);
            try {
                console.time(`${reqLabel} Processing`); const results = await Promise.allSettled(processingPromises); const finalMessages = [];
                results.forEach(r => { if (r.status === 'fulfilled') { const at = r.value.a || {}; const ph = parseBasicHeadersManually(r.value.h || ''); const ha = at.struct ? at.struct.some(p=>p.disposition && (p.disposition.type === 'attachment' || (p.disposition.type === 'inline' && p.disposition.filename))) : false; finalMessages.push({ uid: at.uid, subject: ph.subject, from_address:'', from_name: ph.from, recipient_name: ph.to, // Añadido TO por si se reutiliza para sent
                date: at.date ? (new Date(at.date)).toLocaleString('es-MX',{timeZone:'America/Mexico_City'}) : '?', is_seen: at.flags?.includes('\\Seen')||false, has_attachments: ha, flags: at.flags||[] }); } else { console.error(`${reqLabel} Failed msg processing:`, r.reason); } });
                console.timeEnd(`${reqLabel} Processing`); imap.end(); console.timeEnd(reqLabel);
                if (!res.headersSent) { res.json({ success: true, data: { messages: finalMessages, pagination: { total: totalMessages, currentPage, totalPages, perPage } } }); }
            } catch (procErr) { console.error(`${reqLabel} Processing Error:`, procErr); try { if (imap && imap.state !== 'disconnected') imap.end(); } catch (e) {} console.timeEnd(reqLabel); if (!res.headersSent) { res.status(500).json({ success: false, error: 'PROCESSING_ERROR', message: 'Error procesando mensajes.' }); } }
        });
    } catch (error) { console.error(`${reqLabel} Error:`, error); try { if (imap && imap.state !== 'disconnected') imap.end(); } catch (e) {} console.timeEnd(reqLabel); if (!res.headersSent) { res.status(error.status || 500).json({ success: false, error: error.error || 'INBOX_ERROR', message: error.message || `Error al obtener ${boxName}.` }); } }
});

// GET /api/email/sent (Reutiliza la lógica de /inbox pero cambia el boxName y campos parseados)
app.get('/api/email/sent', requireEmailAuth, async (req, res) => {
    const { user, password } = req.emailCredentials; const boxName = 'Sent'; const page = parseInt(req.query.page) || 1; const perPage = parseInt(req.query.perPage) || 15; const reqLabel = `[${user}] GET /sent p${page}`; console.time(reqLabel); console.log(reqLabel); let imap;
    try {
        console.time(`${reqLabel} Connect`); const { imap: connectedImap, box } = await connectAndOpenBox(user, password, boxName, true); console.timeEnd(`${reqLabel} Connect`); imap = connectedImap;
        const totalMessages = box.messages.total; if (totalMessages === 0) { imap.end(); console.timeEnd(reqLabel); return res.json({ success: true, data: { messages: [], pagination: { total: 0, currentPage: 1, totalPages: 1, perPage: perPage } } }); }
        const totalPages = Math.ceil(totalMessages / perPage); const currentPage = Math.min(Math.max(1, page), totalPages); const startSeq = Math.max(1, totalMessages - ((currentPage - 1) * perPage)); const endSeq = Math.max(1, startSeq - perPage + 1); const sequenceRange = `${endSeq}:${startSeq}`; console.log(`${reqLabel} Total:${totalMessages} Fetch:${sequenceRange}`); const fieldsToFetch = 'HEADER.FIELDS (TO SUBJECT DATE)'; // Pedir TO para enviados
        console.time(`${reqLabel} Fetch`); const fetchResults = imap.fetch(sequenceRange, { bodies: [fieldsToFetch, ''], struct: true, markSeen: false }); const processingPromises = [];
        fetchResults.on('message', (msg, seqno) => { const p = new Promise((resolveMsg, rejectMsg) => { let h='', a={}, hs=false, ar=false; const t=setTimeout(()=>rejectMsg(new Error(`Timeout seq ${seqno}`)),15000); msg.on('body',(s,i)=>{ if(i.which.toUpperCase().startsWith('H')){ s.on('data',c=>h+=c.toString('utf8')); s.once('end',()=>{hs=true;if(ar){clearTimeout(t);resolveMsg({h,a});}}); s.once('error',e=>{clearTimeout(t);rejectMsg(new Error(`Stream err ${seqno}:${e.message}`));});} else {s.on('data',()=>{});s.once('end',()=>{});}}); msg.once('attributes',at=>{a=at;ar=true;if(hs){clearTimeout(t);resolveMsg({h,a});}}); msg.once('error',e=>{clearTimeout(t);rejectMsg(new Error(`Msg err ${seqno}:${e.message}`));}); }); processingPromises.push(p); });
        fetchResults.once('error', (err) => { console.error(`${reqLabel} Fetch Error:`, err); throw new Error(err.message); });
        fetchResults.once('end', async () => {
            console.timeEnd(`${reqLabel} Fetch`);
            try {
                console.time(`${reqLabel} Processing`); const results = await Promise.allSettled(processingPromises); const finalMessages = [];
                results.forEach(r => { if (r.status === 'fulfilled') { const at = r.value.a || {}; const ph = parseBasicHeadersManually(r.value.h || ''); const ha = at.struct ? at.struct.some(p=>p.disposition && (p.disposition.type === 'attachment' || (p.disposition.type === 'inline' && p.disposition.filename))) : false; finalMessages.push({ uid: at.uid, subject: ph.subject, from_address:'', from_name: ph.from, recipient_name: ph.to, // Usar 'to' parseado como recipient_name
                date: at.date ? (new Date(at.date)).toLocaleString('es-MX',{timeZone:'America/Mexico_City'}) : '?', is_seen: at.flags?.includes('\\Seen')||false, has_attachments: ha, flags: at.flags||[] }); } else { console.error(`${reqLabel} Failed msg processing:`, r.reason); } });
                console.timeEnd(`${reqLabel} Processing`); imap.end(); console.timeEnd(reqLabel);
                if (!res.headersSent) { res.json({ success: true, data: { messages: finalMessages, pagination: { total: totalMessages, currentPage, totalPages, perPage } } }); }
            } catch (procErr) { console.error(`${reqLabel} Processing Error:`, procErr); try { if (imap && imap.state !== 'disconnected') imap.end(); } catch (e) {} console.timeEnd(reqLabel); if (!res.headersSent) { res.status(500).json({ success: false, error: 'PROCESSING_ERROR', message: 'Error procesando mensajes.' }); } }
        });
    } catch (error) { console.error(`${reqLabel} Error:`, error); try { if (imap && imap.state !== 'disconnected') imap.end(); } catch (e) {} console.timeEnd(reqLabel); if (!res.headersSent) { res.status(error.status || 500).json({ success: false, error: error.error || 'SENT_ERROR', message: error.message || `Error al obtener ${boxName}.` }); } }
});


// GET /api/email/message/:uid (Detalles)
app.get('/api/email/message/:uid', requireEmailAuth, async (req, res) => {
    const { user, password } = req.emailCredentials; const uid = req.params.uid; if (!uid || !/^\d+$/.test(uid)) { return res.status(400).json({ success: false, error: 'INVALID_UID', message: 'UID inválido.' }); } const boxName = req.query.folder || 'INBOX'; const reqLabel = `[${user}] GET /message/${uid}`; console.time(reqLabel); console.log(`${reqLabel} Folder:${boxName}`); let imap;
    try {
        console.time(`${reqLabel} Connect`); const { imap: connectedImap } = await connectAndOpenBox(user, password, boxName, false); console.timeEnd(`${reqLabel} Connect`); imap = connectedImap;
        console.time(`${reqLabel} Fetch+Parse ${uid}`); const fetchResults = imap.fetch(uid, { bodies: '', struct: true, markSeen: true }); let messageData = null;
        await new Promise((resolveFetch, rejectFetch) => { let bp=false, ar=false; const t=setTimeout(()=>rejectFetch(new Error('Timeout fetch/parse')),30000); fetchResults.on('message',m=>{ m.on('body',(s,i)=>{ parseCompleteMessage(s).then(p=>{messageData=p;bp=true;if(ar){clearTimeout(t);resolveFetch();}}).catch(e=>{clearTimeout(t);rejectFetch(new Error(`Parse err:${e.message}`));}); }); m.once('attributes',at=>{ar=true;if(bp){clearTimeout(t);resolveFetch();}}); m.once('error',e=>{clearTimeout(t);rejectFetch(new Error(`Msg err:${e.message}`));}); }); fetchResults.once('error',e=>{clearTimeout(t);rejectFetch(new Error(`Fetch err:${e.message}`));}); fetchResults.once('end',()=>{ if (!messageData && !bp && !ar) { clearTimeout(t); rejectFetch(new Error(`Msg ${uid} not found/incomplete.`)); } else if (!messageData) { setTimeout(() => { if (!messageData) { clearTimeout(t); rejectFetch(new Error(`Parse not completed ${uid}.`));}}, 500);}}); });
        console.timeEnd(`${reqLabel} Fetch+Parse ${uid}`);
        console.time(`${reqLabel} Prepare Response`); const mail = messageData;
        const responseData = { uid, subject: mail.subject||'(Sin Asunto)', from_address: mail.from?.value[0]?.address||null, from_name: mail.from?.value[0]?.name||mail.from?.value[0]?.address||'?', to: mail.to?.value?.map(a=>({address:a.address,name:a.name}))||[], cc: mail.cc?.value?.map(a=>({address:a.address,name:a.name}))||[], date: mail.date?.toISOString()||null, body_html: mail.html||(mail.text?mail.textAsHtml:null), body_text: mail.text||null, attachments: mail.attachments?.map(a=>({ filename: a.filename||'adjunto', contentType: a.contentType||'app/octet-stream', size: a.size, contentId: a.contentId||null, partId: a.partId||null }))||[] };
        console.timeEnd(`${reqLabel} Prepare Response`); imap.end(); console.timeEnd(reqLabel);
        res.json({ success: true, data: responseData });
    } catch (error) { console.error(`${reqLabel} Error:`, error); try { if (imap && imap.state !== 'disconnected') imap.end(); } catch (e) {} console.timeEnd(reqLabel); let sc=500, ec='MESSAGE_FETCH_FAILED'; if (error.message?.includes('not found')||error.message?.includes('does not exist')){sc=404;ec='MESSAGE_NOT_FOUND';} else if(error.message?.includes('Parse err')){ec='MESSAGE_PARSE_ERROR';} else if(error.message?.includes('Timeout')){sc=504;ec='FETCH_TIMEOUT';} if (!res.headersSent) { res.status(sc).json({ success: false, error: ec, message: error.message||'Error al obtener detalles.' }); } }
});

// POST /api/email/send
app.post('/api/email/send', requireEmailAuth, async (req, res) => {
    const { user, password } = req.emailCredentials; const { to, subject, text, html, cc, bcc, fromName, attachments } = req.body; const reqLabel = `[${user}] POST /send`; console.time(reqLabel); console.log(`${reqLabel} To:${to}`);
    if (!to || !subject || (!text && !html)) { console.timeEnd(reqLabel); return res.status(400).json({ success: false, error: 'MISSING_PARAMS', message: 'Faltan parámetros.' }); }
    const validateEmails = (emails) => { if (!emails) return true; return emails.split(',').every(e => /\S+@\S+\.\S+/.test(e.trim())); }; if (!validateEmails(to) || !validateEmails(cc) || !validateEmails(bcc)) { console.timeEnd(reqLabel); return res.status(400).json({ success: false, error: 'INVALID_RECIPIENT', message: 'Email inválido.' }); }
    let transporter = nodemailer.createTransport({ host: SMTP_HOST, port: SMTP_PORT, secure: SMTP_SECURE, auth: { user, pass: password }, tls: { rejectUnauthorized: false } });
    let mailOptions = { from: `"${fromName || user}" <${user}>`, to, cc, bcc, subject, text, html, attachments: [] };
    if (attachments && Array.isArray(attachments)) { attachments.forEach(a=>{ if(a.filename&&a.content&&a.contentType){ try{ mailOptions.attachments.push({filename:a.filename, content:Buffer.from(a.content,'base64'), contentType:a.contentType}); } catch(e){console.warn(`${reqLabel} Invalid base64 attach skipped:`,a.filename);} } else {console.warn(`${reqLabel} Invalid attach format skipped.`);}}); console.log(`${reqLabel} Processed ${mailOptions.attachments.length} attachments.`); }
    try { console.time(`${reqLabel} SMTP Send`); let info = await transporter.sendMail(mailOptions); console.timeEnd(`${reqLabel} SMTP Send`); console.log(`${reqLabel} Sent OK ID:${info.messageId}`);
        try { console.time(`${reqLabel} Append Sent`); let raw='From: '+mailOptions.from+'\r\nTo: '+to+'\r\n'+(cc?'Cc: '+cc+'\r\n':'')+'Subject: '+subject+'\r\nDate: '+new Date().toUTCString()+'\r\nContent-Type: text/html; charset=utf-8\r\n\r\n'+(html||text); const {imap:cA}=await connectAndOpenBox(user,password,'Sent',false); await util.promisify(cA.append).bind(cA)(raw,{mailbox:'Sent',flags:['\\Seen']}); cA.end(); console.timeEnd(`${reqLabel} Append Sent`); console.log(`${reqLabel} Appended to Sent.`); } catch(appErr){ console.error(`${reqLabel} Failed append Sent:`,appErr.message); console.timeEnd(`${reqLabel} Append Sent`); }
        console.timeEnd(reqLabel); res.json({ success: true, message: 'Correo enviado.', messageId: info.messageId });
    } catch (error) { console.timeEnd(`${reqLabel} SMTP Send`); console.error(`${reqLabel} SMTP Error:`, error); let ec='SEND_FAILED', em='Error al enviar.'; if (error.code==='EAUTH'||error.responseCode===535){ec='AUTH_FAILED';em='Fallo auth SMTP.';} else if(error.code==='EENVELOPE'||[550,551,553,554].includes(error.responseCode)){ec='INVALID_RECIPIENT';em='Destinatario rechazado.';} console.timeEnd(reqLabel); res.status(500).json({ success: false, error: ec, message: em, details: error.message }); }
});

// DELETE /api/email/message/:uid
app.delete('/api/email/message/:uid', requireEmailAuth, async (req, res) => {
    const { user, password } = req.emailCredentials; const uid = req.params.uid; if (!uid || !/^\d+$/.test(uid)) { return res.status(400).json({ success: false, error: 'INVALID_UID', message: 'UID inválido.' }); } const boxName = req.query.folder || 'INBOX'; const reqLabel = `[${user}] DELETE /message/${uid}`; console.time(reqLabel); console.log(`${reqLabel} Folder:${boxName}`); let imap;
    try { const { imap: cD } = await connectAndOpenBox(user, password, boxName, false); imap = cD; console.log(`${reqLabel} Marking ${uid} \\Deleted`); await util.promisify(imap.addFlags).bind(imap)(uid, '\\Deleted'); console.log(`${reqLabel} Expunging ${uid}`); await util.promisify(imap.expunge).bind(imap)([uid]); console.log(`${reqLabel} Delete OK`); imap.end(); console.timeEnd(reqLabel); res.json({ success: true, message: 'Mensaje eliminado.' });
    } catch (error) { console.error(`${reqLabel} Error:`, error); try { if (imap && imap.state !== 'disconnected') imap.end(); } catch (e) {} console.timeEnd(reqLabel); let sc=500; if (error.message?.includes('does not exist')||error.message?.includes('Invalid UID')) sc=404; if (!res.headersSent) { res.status(sc).json({ success: false, error: 'DELETE_FAILED', message: error.message || 'Error al eliminar.' }); } }
});

// POST /api/email/message/:uid/flags
app.post('/api/email/message/:uid/flags', requireEmailAuth, async (req, res) => {
    const { user, password } = req.emailCredentials; const uid = req.params.uid; const { add, remove } = req.body; const boxName = req.query.folder || 'INBOX'; if (!uid || !/^\d+$/.test(uid) || (!add && !remove)) { return res.status(400).json({ success: false, error: 'INVALID_PARAMS', message: 'Parámetros inválidos.' }); } const reqLabel = `[${user}] POST /message/${uid}/flags`; console.time(reqLabel); console.log(`${reqLabel} Folder:${boxName}`, req.body); let imap;
    try { const { imap: cF } = await connectAndOpenBox(user, password, boxName, false); imap = cF; if (add?.length) await util.promisify(imap.addFlags).bind(imap)(uid, add); if (remove?.length) await util.promisify(imap.delFlags).bind(imap)(uid, remove); imap.end(); console.timeEnd(reqLabel); res.json({ success: true, message: 'Flags actualizados.' });
    } catch (error) { console.error(`${reqLabel} Error:`, error); try { if (imap && imap.state !== 'disconnected') imap.end(); } catch (e) {} console.timeEnd(reqLabel); res.status(500).json({ success: false, error: 'FLAG_UPDATE_FAILED', message: error.message || 'Error al actualizar flags.' }); }
});

// GET /api/email/attachment/:uid/:partId
app.get('/api/email/attachment/:uid/:partId', requireEmailAuth, async (req, res) => {
    const { user, password } = req.emailCredentials; const uid = req.params.uid; const partId = req.params.partId; const boxName = req.query.folder || 'INBOX'; if (!uid || !/^\d+$/.test(uid) || !partId ) { return res.status(400).json({ success: false, error: 'INVALID_PARAMS', message: 'Parámetros inválidos.' }); } const reqLabel = `[${user}] GET /attachment/${uid}/${partId}`; console.time(reqLabel); console.log(`${reqLabel} Folder:${boxName}`); let imap;
    try { const { imap: cA } = await connectAndOpenBox(user, password, boxName, true); imap = cA; console.log(`${reqLabel} Fetching struct...`); const fetchStruct = imap.fetch(uid, { bodies: [], struct: true }); let attachmentInfo = null;
        await new Promise((resolveStruct, rejectStruct) => { const t=setTimeout(()=>rejectStruct(new Error('Timeout struct')),15000); fetchStruct.on('message',m=>{m.once('attributes',a=>{clearTimeout(t); function fp(s,id){if(!s)return null;for(let i=0;i<s.length;i++){const p=s[i];if(p.partID===id)return p;if(p.childNodes){const f=fp(p.childNodes,id);if(f)return f;}}return null;} const tp=fp(a.struct,partId); if(tp){attachmentInfo={filename:tp.params?.name||tp.disposition?.params?.filename||`adj_${partId}.dat`, contentType:`${tp.type}/${tp.subtype}`.toLowerCase(), encoding:tp.encoding?.toLowerCase()||null, size:tp.size||null}; resolveStruct();} else {rejectStruct(new Error(`PartID ${partId} not found.`));}}); m.once('error',e=>{clearTimeout(t);rejectStruct(new Error(e.message));});}); fetchStruct.once('error',e=>{clearTimeout(t);rejectStruct(new Error(e.message));}); fetchStruct.once('end',()=>{if(!attachmentInfo)rejectStruct(new Error('Struct end no part.'));}); });
        if (!attachmentInfo) throw new Error('Attach info not found.'); console.log(`${reqLabel} Fetching body part ${partId}...`, attachmentInfo); const fetchBody = imap.fetch(uid, { bodies: `BODY[${partId}]` });
        res.setHeader('Content-Type', attachmentInfo.contentType); const disp = attachmentInfo.contentType.startsWith('image/') || attachmentInfo.contentType === 'application/pdf' ? 'inline' : 'attachment'; res.setHeader('Content-Disposition', `${disp}; filename="${attachmentInfo.filename.replace(/"/g, '\\"')}"`); if (attachmentInfo.size) res.setHeader('Content-Length', attachmentInfo.size);
        await new Promise((resolvePipe, rejectPipe) => { const t=setTimeout(()=>rejectPipe(new Error('Timeout stream')),60000); fetchBody.on('message', m => { m.on('body', (s,i) => { const pt = new PassThrough(); s.pipe(pt).pipe(res); s.once('end', () => { clearTimeout(t); resolvePipe(); }); s.once('error', e => { clearTimeout(t); rejectPipe(new Error(e.message)); }); }); m.once('error', e => { clearTimeout(t); rejectPipe(new Error(e.message)); }); }); fetchBody.once('error', e => { clearTimeout(t); rejectPipe(new Error(e.message)); }); });
        console.log(`${reqLabel} Stream finished.`); imap.end(); console.timeEnd(reqLabel);
    } catch (error) { console.error(`${reqLabel} Error:`, error); try { if (imap && imap.state !== 'disconnected') imap.end(); } catch (e) {} console.timeEnd(reqLabel); if (!res.headersSent) { res.status(500).json({ success: false, error: 'ATTACHMENT_ERROR', message: error.message || 'Error descargar adjunto.' }); } else { res.end(); } }
});
app.get('/api/email/trash', requireEmailAuth, async (req, res) => {
    const { user, password } = req.emailCredentials;
    // --- ¡IMPORTANTE! Ajusta 'Trash' si tu carpeta se llama diferente (ej. 'Papelera') ---
    const boxName = 'Trash';
    // --------------------------------------------------------------------------------
    const page = parseInt(req.query.page) || 1;
    const perPage = parseInt(req.query.perPage) || 15;
    const reqLabel = `[${user}] GET /trash p${page}`;
    console.time(reqLabel); console.log(reqLabel); let imap;
    try {
        // Conectar a la carpeta de Papelera (connectAndOpenBox añadirá prefijo si es necesario)
        console.time(`${reqLabel} Connect`);
        const { imap: connectedImap, box } = await connectAndOpenBox(user, password, boxName, true); // readOnly=true
        console.timeEnd(`${reqLabel} Connect`);
        imap = connectedImap;

        const totalMessages = box.messages.total;
        console.log(`${reqLabel} Total messages in ${boxName}: ${totalMessages}`);

        // Si no hay mensajes, devolver respuesta vacía
        if (totalMessages === 0) {
            imap.end(); console.timeEnd(reqLabel);
            return res.json({ success: true, data: { messages: [], pagination: { total: 0, currentPage: 1, totalPages: 1, perPage: perPage } } });
        }

        // Calcular paginación y rango de secuencia (más recientes primero)
        const totalPages = Math.ceil(totalMessages / perPage);
        const currentPage = Math.min(Math.max(1, page), totalPages);
        const startSeq = Math.max(1, totalMessages - ((currentPage - 1) * perPage));
        const endSeq = Math.max(1, startSeq - perPage + 1);
        const sequenceRange = `${endSeq}:${startSeq}`; // Rango inverso
        console.log(`${reqLabel} Total:${totalMessages} Fetching:${sequenceRange}`);

        // Cabeceras a obtener para la lista (FROM/SUBJECT/DATE son usualmente relevantes en Trash)
        const fieldsToFetch = 'HEADER.FIELDS (FROM SUBJECT DATE)';

        console.time(`${reqLabel} Fetch`);
        const fetchResults = imap.fetch(sequenceRange, { bodies: [fieldsToFetch, ''], struct: true, markSeen: false });
        const processingPromises = [];

        // Procesar cada mensaje recibido del fetch
        fetchResults.on('message', (msg, seqno) => {
            const messagePromise = new Promise((resolveMsg, rejectMsg) => {
                let rawHeaderString = '';
                let attributes = {};
                let headerStreamEnded = false;
                let attributesReceived = false;
                const messageTimeout = setTimeout(() => rejectMsg(new Error(`Timeout processing seq ${seqno}`)), 15000); // 15s timeout

                msg.on('body', (stream, info) => {
                     if (info.which.toUpperCase().startsWith('HEADER.FIELDS')) {
                        stream.on('data', (chunk) => rawHeaderString += chunk.toString('utf8'));
                        stream.once('end', () => {
                            headerStreamEnded = true;
                            if (attributesReceived) { clearTimeout(messageTimeout); resolveMsg({ raw_headers: rawHeaderString, attributes }); }
                        });
                        stream.once('error', (streamErr) => { clearTimeout(messageTimeout); rejectMsg(new Error(`Stream err seq ${seqno}: ${streamErr.message}`)); });
                    } else {
                        stream.on('data', () => {}); stream.once('end', () => {});
                    }
                });
                msg.once('attributes', (attrs) => {
                    attributes = attrs; attributesReceived = true;
                    if (headerStreamEnded) { clearTimeout(messageTimeout); resolveMsg({ raw_headers: rawHeaderString, attributes }); }
                });
                msg.once('error', (msgErr) => { clearTimeout(messageTimeout); rejectMsg(new Error(`Msg err seq ${seqno}: ${msgErr.message}`)); });
            });
            processingPromises.push(messagePromise);
        });

        // Manejar error general del fetch
        fetchResults.once('error', (err) => {
            console.error(`${reqLabel} Fetch Error:`, err);
            // Lanzar error para que lo capture el catch principal
            throw new Error(`Fetch Error in ${boxName}: ${err.message}`);
        });

        // Cuando el fetch termina, procesar todas las promesas
        fetchResults.once('end', async () => {
            console.timeEnd(`${reqLabel} Fetch`);
            console.log(`${reqLabel} IMAP Fetch completed. Waiting for message processing...`);
            try {
                console.time(`${reqLabel} Processing`);
                const results = await Promise.allSettled(processingPromises);
                const finalMessages = [];

                results.forEach((result, index) => {
                    if (result.status === 'fulfilled') {
                        const data = result.value;
                        const attrs = data.attributes || {};
                        const raw_headers = data.raw_headers || '';
                        const parsedHeaders = parseBasicHeadersManually(raw_headers); // Parsear manualmente
                        const hasAttachments = attrs.struct ? attrs.struct.some(p => p.disposition && (p.disposition.type === 'attachment' || (p.disposition.type === 'inline' && p.disposition.filename))) : false;

                        // Construir objeto de mensaje para la respuesta JSON
                        finalMessages.push({
                            uid: attrs.uid,
                            subject: parsedHeaders.subject,
                            from_address: '', // Placeholder, no parseado
                            from_name: parsedHeaders.from, // Usar FROM para la papelera
                            recipient_name: parsedHeaders.to, // Incluir TO por si acaso
                            date: attrs.date ? (new Date(attrs.date)).toLocaleString('es-MX', { timeZone: 'America/Mexico_City' }) : '?',
                            is_seen: attrs.flags?.includes('\\Seen') || false,
                            has_attachments: hasAttachments,
                            flags: attrs.flags || []
                        });
                    } else {
                        // Error al procesar un mensaje individual
                        console.error(`${reqLabel} Failed msg processing at index ${index}:`, result.reason.message);
                    }
                });

                // No es necesario revertir, ya que el fetch se hizo en orden descendente
                console.log(`[${user}] Manual parsing and data prep completed. Final messages count: ${finalMessages.length}`);
                console.timeEnd(`${reqLabel} Processing`);
                imap.end(); // Cerrar conexión IMAP
                console.timeEnd(reqLabel); // Terminar timer general

                // Enviar respuesta JSON exitosa si no se ha enviado ya una de error
                if (!res.headersSent) {
                    res.json({
                        success: true,
                        data: { messages: finalMessages, pagination: { total: totalMessages, currentPage, totalPages, perPage } }
                    });
                }
            } catch (procErr) {
                // Error durante Promise.allSettled o el mapeo final
                console.error(`${reqLabel} Processing Error:`, procErr);
                try { if (imap && imap.state !== 'disconnected') imap.end(); } catch (e) {}
                console.timeEnd(reqLabel);
                if (!res.headersSent) {
                    res.status(500).json({ success: false, error: 'PROCESSING_ERROR', message: 'Error interno procesando mensajes.' });
                }
            }
        }); // Fin fetchResults.once('end')

    } catch (error) { // Captura errores de connectAndOpenBox o errores lanzados antes del 'end' del fetch
        console.error(`${reqLabel} Error:`, error);
        try { if (imap && imap.state !== 'disconnected') imap.end(); } catch (e) {}
        console.timeEnd(reqLabel);
        if (!res.headersSent) {
            res.status(error.status || 500).json({ success: false, error: error.error || 'TRASH_ERROR', message: error.message || `Error al obtener ${boxName}.` });
        }
    }
}); // Fin GET /api/email/trash
// GET /api/email/folders
app.get('/api/email/folders', requireEmailAuth, async (req, res) => {
    const { user, password } = req.emailCredentials; const reqLabel = `[${user}] GET /folders`; console.time(reqLabel); console.log(reqLabel); let imap;
    try {
        // Conectar sin abrir caja específica
        const { imap: cF } = await connectAndOpenBox(user, password, '', true); // BoxName vacío
        imap = cF;
        const getBoxes = util.promisify(imap.getBoxes).bind(imap);
        const foldersRaw = await getBoxes();
        const folders = [];
        // Función recursiva para procesar y añadir prefijo INBOX. si es necesario
        function processFolder(folderObj, pathPrefix = '', isRoot = true) {
            for (const name in folderObj) {
                if (!folderObj.hasOwnProperty(name)) continue;
                const currentFolder = folderObj[name];
                let currentPath = '';
                // Determinar path completo (GoDaddy a veces no necesita prefijo en root level)
                 // Ajuste: No añadir prefijo INBOX. si ya está en el nombre o si es la raíz INBOX
                 if (pathPrefix === '' && name.toUpperCase() === 'INBOX') {
                      currentPath = 'INBOX';
                 } else if (pathPrefix.toUpperCase().startsWith('INBOX')) {
                      currentPath = pathPrefix + currentFolder.delimiter + name;
                 } else if (pathPrefix === '') {
                      currentPath = `INBOX.${name}`; // Asumir prefijo si no es INBOX en raíz
                 } else {
                      currentPath = pathPrefix + currentFolder.delimiter + name; // Heredar prefijo
                 }


                // Corrección: A veces el path ya viene completo, evitar duplicar INBOX.
                if (pathPrefix.toUpperCase() === 'INBOX' && name.toUpperCase().startsWith('INBOX.')) {
                    currentPath = name; // Usar el nombre si ya tiene el prefijo
                } else if (pathPrefix === '' && name.toUpperCase() !== 'INBOX') {
                     // Para carpetas raíz que no son INBOX, añadir prefijo
                     currentPath = `INBOX.${name}`;
                 } else if (pathPrefix === '' && name.toUpperCase() === 'INBOX') {
                     currentPath = 'INBOX'; // Caso raíz INBOX
                 } else {
                      // Para subcarpetas, concatenar normal
                      currentPath = pathPrefix ? pathPrefix + currentFolder.delimiter + name : name;
                 }


                folders.push({ path: currentPath, name: name, attributes: currentFolder.attribs||[], delimiter: currentFolder.delimiter });
                if (currentFolder.children && Object.keys(currentFolder.children).length > 0) {
                    processFolder(currentFolder.children, currentPath, false); // Pasar false para isRoot
                }
            }
        }
        processFolder(foldersRaw); // Empezar procesamiento
        imap.end(); console.timeEnd(reqLabel);
        res.json({ success: true, data: { folders: folders }});
    } catch (error) { console.error(`${reqLabel} Error:`, error); try { if (imap && imap.state !== 'disconnected') imap.end(); } catch (e) {} console.timeEnd(reqLabel); res.status(error.status || 500).json({ success: false, error: error.error || 'FOLDER_LIST_ERROR', message: error.message || 'Error listar carpetas.' }); }
});

// --- Iniciar Servidor ---
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Microservicio Email (Completo v3) corriendo en http://localhost:${PORT}`);
});