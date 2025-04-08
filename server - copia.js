// server.js
require('dotenv').config(); // Carga .env (útil en desarrollo)
const util = require('util'); // Para promisify
const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors'); // Habilitar CORS si PHP y Node están en dominios/puertos diferentes
const Imap = require('node-imap');
const { simpleParser } = require('mailparser'); // Importar simpleParser
const nodemailer = require('nodemailer');

const app = express();
app.use(bodyParser.json());
app.use(cors()); // Configura CORS según tus necesidades

// --- Configuración ---
const DEFAULT_EMAIL_USER = process.env.DEFAULT_EMAIL_USER || null; // Ya no es necesario si siempre viene en header
const IMAP_HOST = process.env.IMAP_HOST || 'felobe.com';
const IMAP_PORT = process.env.IMAP_PORT ? parseInt(process.env.IMAP_PORT) : 993;
const IMAP_TLS = process.env.IMAP_TLS !== 'false'; // true por defecto, false si IMAP_TLS='false'
const SMTP_HOST = process.env.SMTP_HOST || IMAP_HOST; // Usar mismo host por defecto
const SMTP_PORT = process.env.SMTP_PORT ? parseInt(process.env.SMTP_PORT) : 465;
const SMTP_SECURE = process.env.SMTP_SECURE !== 'false'; // true por defecto (para puerto 465/SSL)

// --- Middleware para Autenticación Básica ---
// Verifica que los headers x-email-user y x-email-password existan
const requireEmailAuth = (req, res, next) => {
    const emailUser = req.headers['x-email-user'];
    const password = req.headers['x-email-password'];

    if (!emailUser || !password) {
        console.error(`[${new Date().toISOString()}] Auth Error: Missing x-email-user or x-email-password headers.`);
        return res.status(401).json({ success: false, error: 'AUTH_REQUIRED', message: 'Faltan credenciales de correo en la cabecera.' });
    }
    // Pasar credenciales al request para uso posterior
    req.emailCredentials = { user: emailUser, password: password };
    console.log(`[${new Date().toISOString()}] Auth Check OK for user: ${emailUser}`);
    next(); // Continuar si las cabeceras existen
};

// --- Funciones Helper IMAP ---

/**
 * Conecta y abre una carpeta IMAP. Devuelve el objeto Imap y la caja abierta.
 * Maneja la conexión y desconexión básica.
 * @param {string} emailUser
 * @param {string} password
 * @param {string} boxName Nombre de la carpeta (ej. 'INBOX', 'Sent')
 * @returns {Promise<{imap: Imap, box: object}>} Promesa que resuelve con imap y box o rechaza con error.
 */
function connectAndOpenBox(emailUser, password, boxName = 'INBOX') {
    return new Promise((resolve, reject) => {
        const imap = new Imap({
            user: emailUser, password: password, host: IMAP_HOST, port: IMAP_PORT, tls: IMAP_TLS,
            // Añadir opciones de TLS si son necesarias (ej. rejectUnauthorized)
             tlsOptions: { rejectUnauthorized: false } // ¡CUIDADO! Solo si tienes problemas de certificado, menos seguro.
        });

        imap.once('ready', () => {
            console.log(`[${emailUser}] IMAP Ready. Opening box: ${boxName}`);
            imap.openBox(boxName, false, (err, box) => { // false = read-only (más seguro si solo lees) -> CAMBIAR a false si es posible
                if (err) {
                    console.error(`[${emailUser}] Error opening box ${boxName}:`, err);
                    imap.end();
                    return reject({ status: 500, error: 'FOLDER_OPEN_ERROR', message: `Error al abrir carpeta ${boxName}: ${err.message}` });
                }
                console.log(`[${emailUser}] Box ${boxName} opened.`);
                resolve({ imap, box }); // Devuelve la conexión y la caja abierta
            });
        });

        imap.once('error', (err) => {
            console.error(`[${emailUser}] IMAP Connection Error:`, err);
            // Intentar cerrar conexión si aún está en algún estado intermedio
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

/**
 * Parsea el stream de cabeceras IMAP usando mailparser.
 * @param {ReadableStream} stream
 * @returns {Promise<object>} Promesa que resuelve con el objeto de cabeceras parseado.
 */
function parseHeaders(stream) {
    return new Promise((resolve, reject) => {
        simpleParser(stream, (err, mail) => {
            if (err) {
                return reject(err);
            }
            // Devolvemos solo las cabeceras importantes (o todo el objeto mail.headers si prefieres)
            resolve({
                subject: mail.subject,
                from: mail.from?.value[0], // Primer remitente
                to: mail.to?.value,       // Array de destinatarios
                cc: mail.cc?.value,       // Array de CC
                date: mail.date,          // Objeto Date
                messageId: mail.messageId
            });
        });
    });
}


// --- Endpoints API ---

/**
 * Endpoint: POST /api/email/validate (NUEVO)
 * Valida las credenciales de correo sin hacer nada más.
 * Requiere headers: x-email-user, x-email-password
 */
app.post('/api/email/validate', requireEmailAuth, async (req, res) => {
    const { user, password } = req.emailCredentials;
    console.log(`[${user}] Endpoint /validate called.`);
    try {
        // Solo conectar y desconectar para validar
        const { imap } = await connectAndOpenBox(user, password, 'INBOX'); // Intenta abrir INBOX
        imap.end(); // Cierra la conexión inmediatamente
        console.log(`[${user}] Validation successful.`);
        res.json({ success: true, message: 'Credenciales válidas.' });
    } catch (error) {
        console.error(`[${user}] Validation failed:`, error);
        // Devolver el código y mensaje de error específico si es posible
        res.status(error.status || 500).json({ success: false, error: error.error || 'VALIDATION_FAILED', message: error.message || 'Error de validación IMAP.' });
    }
});


/**
 * Endpoint: GET /api/email/inbox
 * Obtiene mensajes paginados de la bandeja de entrada (solo cabeceras/flags).
 * Requiere headers: x-email-user, x-email-password
 * Query params: page, perPage
 */
app.get('/api/email/inbox', requireEmailAuth, async (req, res) => {
    const { user, password } = req.emailCredentials;
    const page = parseInt(req.query.page) || 1;
    const perPage = parseInt(req.query.perPage) || 25;
    const boxName = 'INBOX'; // O hacerlo dinámico si es necesario

    console.log(`[${user}] Endpoint /inbox called. Page: ${page}, PerPage: ${perPage}`);

    let imap; // Para poder cerrarla en el finally
    try {
        const { imap: connectedImap, box } = await connectAndOpenBox(user, password, boxName);
        imap = connectedImap; // Guardar referencia para finally

        // Usar el número total de mensajes reportado por la caja
        const totalMessages = box.messages.total;
        console.log(`[${user}] Total messages in ${boxName}: ${totalMessages}`);

        if (totalMessages === 0) {
            imap.end();
            return res.json({ success: true, data: { messages: [], pagination: { total: 0, currentPage: 1, totalPages: 1, perPage: perPage } } });
        }

        const totalPages = (perPage > 0) ? Math.ceil(totalMessages / perPage) : 1;
        const currentPage = Math.min(Math.max(1, page), totalPages); // Asegurar que la página sea válida
        const startSeq = Math.max(1, totalMessages - (currentPage * perPage) + 1); // Calcular inicio secuencia para DESC
        const endSeq = totalMessages - ((currentPage - 1) * perPage);          // Calcular fin secuencia para DESC
        const sequenceRange = `${startSeq}:${endSeq}`; // Rango para fetch

        console.log(`[${user}] Fetching sequence range: ${sequenceRange} (Total: ${totalMessages}, Page: ${currentPage})`);

        const messagesData = []; // Array para guardar datos parseados
        // Promisify imap.fetch para usar async/await
        const imapFetch = util.promisify(imap.fetch).bind(imap);

        // Obtener cabeceras y flags para el rango de secuencia calculado
        // NOTA: Los servidores IMAP devuelven mensajes en orden ASCENDENTE por secuencia.
        //       Pedimos el rango calculado y LUEGO invertiremos el array resultante en PHP/JS.
        const fetchResults = imap.fetch(sequenceRange, {
            bodies: ['HEADER.FIELDS (FROM TO CC SUBJECT DATE MESSAGE-ID)', ''], // Pedir cabeceras y flags (body vacío)
            struct: true, // Necesario para info de adjuntos
            markSeen: false // No marcar como leído al hacer fetch
        });

        // Usar un array de promesas para parsear cada mensaje
        const parsingPromises = [];

        fetchResults.on('message', (msg, seqno) => {
            const p = new Promise((resolveMsg) => {
                let headers = {};
                let attributes = {};
                let bodyStreamEnded = false;
                let attributesEnded = false;

                msg.on('body', (stream, info) => {
                    // Parsear solo las cabeceras pedidas
                    if (info.which.toUpperCase().startsWith('HEADER.FIELDS')) {
                        parseHeaders(stream).then(parsed => {
                            headers = parsed; // Guardar cabeceras parseadas
                            if (attributesEnded) resolveMsg({ headers, attributes }); // Resolver si attributes ya terminó
                        }).catch(parseErr => {
                             console.error(`[${user}] Error parsing headers for seq ${seqno}:`, parseErr);
                             if (attributesEnded) resolveMsg({ headers: {}, attributes }); // Resolver con headers vacíos si falla parseo
                        });
                    } else {
                        // Ignorar otros streams (como el body '') para ahorrar memoria
                         stream.on('data', () => {}); // Consumir datos para que 'end' se dispare
                         stream.on('end', () => {
                              bodyStreamEnded = true;
                             // console.log(`[${user}] Body stream ended for seq ${seqno}`);
                             if (attributesEnded && !headers.subject) resolveMsg({ headers, attributes }); // Resolver si attributes terminó y headers está listo
                         });
                    }
                });

                msg.once('attributes', (attrs) => {
                    attributes = attrs; // Guardar atributos (uid, flags, date)
                });

                msg.once('end', () => {
                     attributesEnded = true;
                     // console.log(`[${user}] Message ended for seq ${seqno}`);
                     // Asegurarse que el parseo de headers haya terminado o fallado
                     // Esto puede necesitar un timeout o una mejor gestión de promesas si parseHeaders tarda mucho
                     // Por ahora, asumimos que parseHeaders resuelve razonablemente rápido
                     if (headers.subject || bodyStreamEnded) { // Resolver si headers está listo o si el body stream (que ignoramos) terminó
                         resolveMsg({ headers, attributes });
                     }
                     // Si no, la promesa se resolverá dentro del callback de parseHeaders
                });
            });
            parsingPromises.push(p); // Añadir promesa al array
        }); // Fin fetchResults.on('message')

        fetchResults.once('error', (err) => {
            console.error(`[${user}] IMAP Fetch Error:`, err);
            try { if (imap.state !== 'disconnected') imap.end(); } catch (e) {}
            return reject({ status: 500, error: 'IMAP_FETCH_ERROR', message: `Error al obtener mensajes: ${err.message}` });
        });

        fetchResults.once('end', async () => {
            console.log(`[${user}] IMAP Fetch completed.`);
            try {
                // Esperar a que todas las promesas de parseo se resuelvan
                const rawMessagesData = await Promise.all(parsingPromises);
                console.log(`[${user}] Parsing completed. Messages processed: ${rawMessagesData.length}`);

                // Formatear para la respuesta JSON
                const finalMessages = rawMessagesData.map(data => {
                    const attrs = data.attributes || {};
                    const heads = data.headers || {};
                    const fromInfo = heads.from || {};
                    // Determinar si tiene adjuntos (simplificado, mirar struct si es necesario)
                    const hasAttachments = attrs.struct ? attrs.struct.some(part => part.disposition && (part.disposition.type === 'attachment' || (part.disposition.type === 'inline' && part.disposition.filename))) : false;

                    return {
                        uid: attrs.uid,
                        // sequence_id: attrs.seqno, // node-imap no lo pone en attributes, viene como 2do arg de fetchResults.on('message')
                        subject: heads.subject || '(Sin Asunto)',
                        from_address: fromInfo.address || '?',
                        from_name: fromInfo.name || fromInfo.address || '?',
                        // Formatear fecha desde atributos (más fiable que la cabecera)
                        date: attrs.date ? (new Date(attrs.date)).toLocaleString('es-MX', { timeZone: 'America/Mexico_City' }) : '?',
                        is_seen: attrs.flags ? attrs.flags.includes('\\Seen') : false,
                        has_attachments: hasAttachments, // Indicador de adjuntos
                        flags: attrs.flags || [] // Pasar todos los flags
                    };
                }).reverse(); // Invertir para tener los más recientes primero (ya que fetch devuelve en orden ASC)

                console.log(`[${user}] Data prepared for JSON response.`);
                imap.end(); // Cerrar conexión
                res.json({
                    success: true,
                    data: {
                        messages: finalMessages,
                        pagination: {
                            total: totalMessages,
                            currentPage: currentPage,
                            totalPages: totalPages,
                            perPage: perPage
                        }
                    }
                });
            } catch (processingError) {
                console.error(`[${user}] Error processing messages after fetch:`, processingError);
                 try { if (imap.state !== 'disconnected') imap.end(); } catch (e) {}
                res.status(500).json({ success: false, error: 'PROCESSING_ERROR', message: 'Error interno al procesar mensajes.' });
            }
        }); // Fin fetchResults.once('end')

    } catch (error) {
        console.error(`[${user}] Error en /inbox:`, error);
        // Asegurarse de cerrar IMAP si se abrió
        try { if (imap && imap.state !== 'disconnected') imap.end(); } catch (e) {}
        res.status(error.status || 500).json({ success: false, error: error.error || 'UNKNOWN_ERROR', message: error.message || 'Error desconocido.' });
    }
});

/**
 * Endpoint: POST /api/email/send
 * Envía un correo usando Nodemailer.
 * Requiere headers: x-email-user, x-email-password
 * Body JSON: { to, subject, text, html, cc, bcc }
 */
app.post('/api/email/send', requireEmailAuth, async (req, res) => {
    const { user, password } = req.emailCredentials;
    const { to, subject, text, html, cc, bcc } = req.body;

    console.log(`[${user}] Endpoint /send called. To: ${to}`);

    if (!to || !subject || (!text && !html)) {
        return res.status(400).json({ success: false, error: 'MISSING_PARAMS', message: 'Faltan parámetros requeridos (to, subject, text/html).' });
    }

    // Validar destinatarios (simple)
    const validateEmails = (emails) => {
        if (!emails) return true; // Permitir vacío para CC/BCC
        return emails.split(',').every(email => /\S+@\S+\.\S+/.test(email.trim()));
    };
    if (!validateEmails(to) || !validateEmails(cc) || !validateEmails(bcc)) {
         return res.status(400).json({ success: false, error: 'INVALID_RECIPIENT', message: 'Una o más direcciones de correo son inválidas.' });
    }

    // Crear transporter SMTP
    let transporter = nodemailer.createTransport({
        host: SMTP_HOST, port: SMTP_PORT, secure: SMTP_SECURE, // true para 465 (SSL), false para otros (STARTTLS)
        auth: { user: user, pass: password },
        tls: { rejectUnauthorized: false } // ¡CUIDADO! Solo si tienes problemas de certificado.
    });

    // Opciones del correo
    let mailOptions = {
        from: `"${req.body.fromName || user}" <${user}>`, // Usar nombre si se envía, o solo email
        to: to, // String separado por comas
        subject: subject,
        text: text, // Cuerpo texto plano
        html: html  // Cuerpo HTML
    };
    if (cc) mailOptions.cc = cc;
    if (bcc) mailOptions.bcc = bcc;
    // TODO: Manejo de adjuntos (requiere recibir archivos en Node.js)

    try {
        console.log(`[${user}] Enviando correo via SMTP...`);
        let info = await transporter.sendMail(mailOptions);
        console.log(`[${user}] Correo enviado OK. Message ID: ${info.messageId}`);
        // Opcional: Guardar copia en 'Sent' usando IMAP aquí
        res.json({ success: true, message: 'Correo enviado correctamente.', messageId: info.messageId });
    } catch (error) {
        console.error(`[${user}] Error al enviar correo SMTP:`, error);
        // Devolver errores específicos si es posible
        let errorCode = 'SEND_FAILED';
        let errorMsg = 'Error al enviar el correo.';
        if (error.code === 'EAUTH' || error.responseCode === 535) { // Error de autenticación SMTP
            errorCode = 'AUTH_FAILED';
            errorMsg = 'Fallo de autenticación SMTP.';
        } else if (error.code === 'EENVELOPE' || error.responseCode === 550 || error.responseCode === 554) { // Error destinatario
            errorCode = 'INVALID_RECIPIENT';
            errorMsg = 'Dirección de destinatario rechazada por el servidor.';
        }
        res.status(500).json({ success: false, error: errorCode, message: errorMsg, details: error.message });
    }
});

// --- Endpoints Adicionales (NECESITARÁS IMPLEMENTARLOS) ---

// GET /api/email/message/:uid - Obtener detalles (cuerpo, adjuntos)
app.get('/api/email/message/:uid', requireEmailAuth, async (req, res) => {
    const { user, password } = req.emailCredentials;
    const uid = req.params.uid;
    const boxName = req.query.folder || 'INBOX'; // Permitir especificar carpeta
    console.log(`[${user}] Endpoint /message/${uid} called. Folder: ${boxName}`);
    // TODO: Implementar lógica similar a inbox pero para un solo mensaje
    //       Usar imap.fetch con bodies: '' para obtener cuerpo completo
    //       Parsear cuerpo y adjuntos con mailparser
    //       Marcar como leído si se abre
    res.status(501).json({ success: false, error: 'NOT_IMPLEMENTED', message: 'Endpoint de detalle no implementado.' });
});

// DELETE /api/email/message/:uid - Eliminar mensaje
app.delete('/api/email/message/:uid', requireEmailAuth, async (req, res) => {
     const { user, password } = req.emailCredentials;
     const uid = req.params.uid;
     const boxName = req.query.folder || 'INBOX';
     console.log(`[${user}] Endpoint DELETE /message/${uid} called. Folder: ${boxName}`);
    // TODO: Implementar lógica: conectar, abrir carpeta, buscar mensaje por UID,
    //       intentar mover a Papelera (imap.move()), si no, eliminar (imap.addFlags(['\\Deleted']) + imap.expunge()?)
    res.status(501).json({ success: false, error: 'NOT_IMPLEMENTED', message: 'Endpoint de eliminación no implementado.' });
});

// POST /api/email/message/:uid/flags - Modificar flags (leído/no leído)
app.post('/api/email/message/:uid/flags', requireEmailAuth, async (req, res) => {
     const { user, password } = req.emailCredentials;
     const uid = req.params.uid;
     const { add, remove } = req.body; // Espera { add: ["\\Seen"], remove: [] } o viceversa
     const boxName = req.query.folder || 'INBOX';
     console.log(`[${user}] Endpoint POST /message/${uid}/flags called. Folder: ${boxName}`, req.body);
    // TODO: Implementar lógica: conectar, abrir carpeta, usar imap.addFlags() o imap.delFlags()
    res.status(501).json({ success: false, error: 'NOT_IMPLEMENTED', message: 'Endpoint de flags no implementado.' });
});

// GET /api/email/attachment/:uid/:attachmentFilename - Descargar adjunto
app.get('/api/email/attachment/:uid/:attachmentFilename', requireEmailAuth, async (req, res) => {
     const { user, password } = req.emailCredentials;
     const uid = req.params.uid;
     const filename = req.params.attachmentFilename; // Ya está urldecode por express
     const boxName = req.query.folder || 'INBOX';
      console.log(`[${user}] Endpoint GET /attachment/${uid}/${filename} called. Folder: ${boxName}`);
     // TODO: Implementar lógica: conectar, abrir, buscar mensaje, buscar adjunto por nombre,
     //       obtener contenido (stream si es posible), establecer headers correctos (Content-Type, Content-Disposition) y enviar.
    res.status(501).json({ success: false, error: 'NOT_IMPLEMENTED', message: 'Endpoint de adjuntos no implementado.' });
});

// GET /api/email/folders - Listar carpetas
app.get('/api/email/folders', requireEmailAuth, async (req, res) => {
     const { user, password } = req.emailCredentials;
     console.log(`[${user}] Endpoint /folders called.`);
     let imap;
     try {
        const { imap: connectedImap } = await connectAndOpenBox(user, password, 'INBOX'); // Conectar a INBOX para listar
        imap = connectedImap;
        const imapGetFolders = util.promisify(imap.getBoxes).bind(imap); // Promisify getBoxes
        const foldersRaw = await imapGetFolders(); // Obtener estructura de carpetas

        // Procesar para obtener una lista simple
        const folders = [];
        function processFolder(folderObj, pathPrefix = '') {
            for (const name in folderObj) {
                const currentFolder = folderObj[name];
                const currentPath = pathPrefix ? pathPrefix + currentFolder.delimiter + name : name;
                // Obtener conteo no leídos (puede ser lento)
                let unreadCount = 0;
                // try {
                //     const box = await util.promisify(imap.openBox).bind(imap)(currentPath, true);
                //     unreadCount = box.messages.unseen;
                //     await util.promisify(imap.closeBox).bind(imap)(false); // No expurgar al cerrar
                // } catch(e) { console.warn(`Could not get unread for ${currentPath}`); }

                folders.push({
                    path: currentPath,
                    name: name,
                    attributes: currentFolder.attribs || [],
                    delimiter: currentFolder.delimiter,
                    unread: unreadCount // Añadir conteo
                });
                // Recursivo si tiene hijos
                if (currentFolder.children && Object.keys(currentFolder.children).length > 0) {
                    processFolder(currentFolder.children, currentPath);
                }
            }
        }
        processFolder(foldersRaw);
        imap.end();
        res.json({ success: true, data: { folders: folders } });

     } catch (error) {
         console.error(`[${user}] Error listing folders:`, error);
         try { if (imap && imap.state !== 'disconnected') imap.end(); } catch (e) {}
         res.status(error.status || 500).json({ success: false, error: error.error || 'FOLDER_LIST_ERROR', message: error.message || 'Error al listar carpetas.' });
     }
});


// --- Iniciar Servidor ---
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Microservicio Email corriendo en http://localhost:${PORT}`);
});