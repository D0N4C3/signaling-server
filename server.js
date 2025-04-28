// server.js

require('dotenv').config();

const express = require('express');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const http = require('http');
const { Server } = require('socket.io');
const winston = require('winston');
const admin = require('firebase-admin');

// 1) Firebase Admin
admin.initializeApp({
  credential: admin.credential.cert({
    project_id: process.env.FIREBASE_PROJECT_ID,
    private_key_id: process.env.FIREBASE_PRIVATE_KEY_ID,
    private_key: process.env.FIREBASE_PRIVATE_KEY.replace(/\\n/g, '\n'),
    client_email: process.env.FIREBASE_CLIENT_EMAIL,
    client_id: process.env.FIREBASE_CLIENT_ID,
    auth_uri: 'https://accounts.google.com/o/oauth2/auth',
    token_uri: 'https://oauth2.googleapis.com/token',
    auth_provider_x509_cert_url:
      'https://www.googleapis.com/oauth2/v1/certs',
    client_x509_cert_url: `https://www.googleapis.com/robot/v1/metadata/x509/${encodeURIComponent(
      process.env.FIREBASE_CLIENT_EMAIL,
    )}`,
  }),
});

// 2) Express + security
const app = express();
app.use(helmet());
app.use(express.json());
app.use(
  rateLimit({
    windowMs: 60_000,
    max: 200,
  }),
);

app.get('/health', (_req, res) =>
  res.json({ status: 'ok', timestamp: Date.now() }),
);

// 3) Logger
const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json(),
  ),
  transports: [new winston.transports.Console()],
});

// 4) HTTP + Socket.IO
const httpServer = http.createServer(app);
const io = new Server(httpServer, {
  cors: { origin: '*', methods: ['GET', 'POST'] },
});

// 5) (Optional) Auth middleware — disabled until the client starts sending tokens
/*
io.use(async (socket, next) => {
  try {
    const token = socket.handshake.auth.token;
    if (!token) throw new Error('No token');
    const decoded = await admin.auth().verifyIdToken(token);
    socket.data.user = decoded;
    next();
  } catch (err) {
    logger.warn('Unauthorized socket', { error: err.message });
    next(new Error('Unauthorized'));
  }
});
*/

// 6) Safe wrapper
function safeHandler(fn) {
  return (payload, cb = () => {}) => {
    try {
      fn(payload, cb);
    } catch (err) {
      logger.error('Handler error', { err });
      cb({ error: 'internal_error' });
    }
  };
}

// 7) Signaling & annotations
io.on('connection', socket => {
  logger.info('📡 Client connected', { socketId: socket.id });

  socket.on('join', safeHandler((room, cb) => {
    if (typeof room !== 'string') return cb({ error: 'invalid_room' });
    socket.join(room);
    cb({ success: true });
  }));

  ['offer', 'answer', 'candidate'].forEach(evt =>
    socket.on(evt, safeHandler((data, cb) => {
      if (
        !data ||
        typeof data.room !== 'string' ||
        (evt === 'candidate'
          ? typeof data.candidate !== 'object'
          : typeof data.sdp !== 'string')
      ) {
        return cb({ error: 'invalid_payload' });
      }
      socket.to(data.room).emit(evt, data);
      cb({ success: true });
    })),
  );

  socket.on('draw', safeHandler((data, cb) => {
    socket.to(data.room).emit('draw', data);
    cb({ success: true });
  }));

  socket.on('undo', safeHandler((room, cb) => {
    socket.to(room).emit('undo');
    cb({ success: true });
  }));

  socket.on('clear', safeHandler((room, cb) => {
    socket.to(room).emit('clear');
    cb({ success: true });
  }));

  socket.on('color', safeHandler((data, cb) => {
    socket.to(data.room).emit('color', data.color);
    cb({ success: true });
  }));

  socket.on('disconnect', reason => {
    logger.info('❌ Client disconnected', { socketId: socket.id, reason });
  });
});

// 8) Launch
const PORT = process.env.PORT || 3000;
httpServer.listen(PORT, () => {
  logger.info(`🚀 Signaling server running on port ${PORT}`);
});
