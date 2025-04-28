// signaling-server/index.js
require('dotenv').config();

const express = require('express');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const http = require('http');
const { Server } = require('socket.io');
const winston = require('winston');
const admin = require('firebase-admin');

// ——————————
// 1) Init Firebase Admin (for verifying ID tokens)
// ——————————
admin.initializeApp({
  credential: admin.credential.cert(
    JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT)
  ),
});

// ——————————
// 2) Setup Express with security middlewares
// ——————————
const app = express();
app.use(helmet());
app.use(express.json());
app.use(
  rateLimit({
    windowMs: 1 * 60 * 1000, // 1 minute
    max: 200, // limit each IP to 200 requests per windowMs
  })
);

// Health check for uptime monitoring
app.get('/health', (_req, res) => {
  res.json({ status: 'ok', timestamp: Date.now() });
});

// ——————————
// 3) Setup Winston logger
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
// 4) Create HTTP + Socket.IO server
// ——————————
const httpServer = createServer(app);
const io = new Server(httpServer, {
  cors: {
    origin: process.env.CORS_ORIGINS.split(','),
    methods: ['GET', 'POST'],
    credentials: true,
  },
});

// ——————————
// 5) (Optional) Redis adapter for scaling
// ——————————
if (process.env.REDIS_URL) {
  const pubClient = createClient({ url: process.env.REDIS_URL });
  const subClient = pubClient.duplicate();
  await Promise.all([pubClient.connect(), subClient.connect()]);
  io.adapter(createAdapter(pubClient, subClient));
  logger.info('🚀 Redis adapter enabled for scaling');
}

// ——————————
// 6) Authenticate each socket via Firebase ID token
// ——————————
io.use(async (socket, next) => {
  try {
    const token = socket.handshake.auth.token;
    if (!token) throw new Error('No auth token');
    const decoded = await admin.auth().verifyIdToken(token);
    socket.data.user = decoded; // attach user info
    next();
  } catch (err) {
    logger.warn('Unauthorized socket', { error: err.message });
    next(new Error('Unauthorized'));
  }
});

// ——————————
// 7) Helper: wrap handlers with ack support & validation
// ——————————
function safeHandler(fn) {
  return (payload, callback = () => {}) => {
    try {
      fn(payload, callback);
    } catch (err) {
      logger.error('Handler error', { err });
      callback({ error: 'internal_error' });
    }
  };
}

// ——————————
// 8) Core socket logic
// ——————————
io.on('connection', socket => {
  const uid = socket.data.user.uid;
  logger.info('Client connected', { socketId: socket.id, uid });

  // Join a session room
  socket.on(
    'join',
    safeHandler((room, cb) => {
      if (typeof room !== 'string') return cb({ error: 'invalid_room' });
      socket.join(room);
      logger.info('Joined room', { uid, room });
      cb({ success: true });
    })
  );

  // WebRTC: offer / answer / candidate
  ['offer', 'answer', 'candidate'].forEach(event =>
    socket.on(
      event,
      safeHandler((payload, cb) => {
        if (
          !payload ||
          typeof payload.room !== 'string' ||
          typeof payload[event === 'candidate' ? 'candidate' : 'sdp'] !==
            'string'
        ) {
          return cb({ error: 'invalid_payload' });
        }
        socket.to(payload.room).emit(event, {
          sender: uid,
          ...payload,
        });
        cb({ success: true });
      })
    )
  );

  // Annotation controls: undo / clear / color
  socket.on(
    'undo',
    safeHandler((room, cb) => {
      if (typeof room !== 'string') return cb({ error: 'invalid_room' });
      socket.to(room).emit('undo');
      cb({ success: true });
    })
  );

  socket.on(
    'clear',
    safeHandler((room, cb) => {
      if (typeof room !== 'string') return cb({ error: 'invalid_room' });
      socket.to(room).emit('clear');
      cb({ success: true });
    })
  );

  socket.on(
    'color',
    safeHandler((payload, cb) => {
      if (
        !payload ||
        typeof payload.room !== 'string' ||
        typeof payload.color !== 'number'
      ) {
        return cb({ error: 'invalid_payload' });
      }
      socket.to(payload.room).emit('color', payload.color);
      cb({ success: true });
    })
  );

  // Stroke drawing
  socket.on('draw', safeHandler((payload, cb) => {
    // basic validation
    if (
      !payload ||
      typeof payload.room !== 'string' ||
      !Array.isArray(payload.points) ||
      typeof payload.color !== 'number' ||
      typeof payload.width !== 'number'
    ) {
      return cb({ error: 'invalid_payload' });
    }
    // broadcast to all other clients in the room
    socket.to(payload.room).emit('draw', {
      points: payload.points,
      color: payload.color,
      width: payload.width,
    });
    cb({ success: true });
  }));


  socket.on('disconnect', reason => {
    logger.info('Client disconnected', { socketId: socket.id, reason });
  });
});

// ——————————
// 9) Start the server
// ——————————
const PORT = process.env.PORT || 3000;
httpServer.listen(PORT, () => {
  logger.info(`🚀 Signaling server is live on port ${PORT}`);
});
