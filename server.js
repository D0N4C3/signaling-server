// server.js

// 1) Load env
require('dotenv').config();

const express = require('express');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const http = require('http');
const { Server } = require('socket.io');
const winston = require('winston');
const admin = require('firebase-admin');

// ——————————
// 2) Firebase Admin
// ——————————
admin.initializeApp({
  credential: admin.credential.cert(
    JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT)
  ),
});

// ——————————
// 3) Express + security
// ——————————
const app = express();
app.use(helmet());
app.use(express.json());
app.use(
  rateLimit({
    windowMs: 60_000,
    max: 200,
  })
);

app.get('/health', (_req, res) =>
  res.json({ status: 'ok', timestamp: Date.now() })
);

// ——————————
// 4) Logger
// ——————————
const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json()
  ),
  transports: [new winston.transports.Console()],
});

// ——————————
// 5) HTTP + Socket.IO
// ——————————
const httpServer = http.createServer(app);
const io = new Server(httpServer, {
  cors: { origin: '*', methods: ['GET','POST'] },
});

// ——————————
// 6) (Optional) Auth middleware
// ——————————
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

// ——————————
// 7) Safe handler
// ——————————
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

// ——————————
// 8) Socket logic
// ——————————
io.on('connection', socket => {
  const uid = socket.data.user?.uid;
  logger.info('📡 Client connected', { socketId: socket.id, uid });

  // join
  socket.on('join', safeHandler((room, cb) => {
    if (typeof room !== 'string') return cb({ error: 'invalid_room' });
    socket.join(room);
    cb({ success: true });
  }));

  // signaling
  ['offer','answer','candidate'].forEach(evt =>
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
    }))
  );

  // annotation draw
  socket.on('draw', safeHandler((data, cb) => {
    if (
      !data ||
      typeof data.room !== 'string' ||
      !Array.isArray(data.points) ||
      typeof data.color !== 'number' ||
      typeof data.width !== 'number'
    ) {
      return cb({ error: 'invalid_payload' });
    }
    socket.to(data.room).emit('draw', data);
    cb({ success: true });
  }));

  // undo / clear / color
  socket.on('undo', safeHandler((room, cb) => {
    if (typeof room !== 'string') return cb({ error: 'invalid_room' });
    socket.to(room).emit('undo');
    cb({ success: true });
  }));
  socket.on('clear', safeHandler((room, cb) => {
    if (typeof room !== 'string') return cb({ error: 'invalid_room' });
    socket.to(room).emit('clear');
    cb({ success: true });
  }));
  socket.on('color', safeHandler((data, cb) => {
    if (
      !data ||
      typeof data.room !== 'string' ||
      typeof data.color !== 'number'
    ) {
      return cb({ error: 'invalid_payload' });
    }
    socket.to(data.room).emit('color', data.color);
    cb({ success: true });
  }));

  socket.on('disconnect', reason => {
    logger.info('❌ Client disconnected', { socketId: socket.id, reason });
  });
});

// ——————————
// 9) Start server
// ——————————
const PORT = process.env.PORT || 3000;
httpServer.listen(PORT, () => {
  logger.info(`🚀 Signaling server running on port ${PORT}`);
});
