require('dotenv').config();
const express = require('express');
const http = require('http');
const cors = require('cors');
const { Server } = require('socket.io');
const { createAdapter } = require('@socket.io/redis-adapter');
const { createClient } = require('ioredis');

const app = express();
app.use(cors());
app.get('/', (_req, res) => res.send('🛠 AR Remote Signaling Server is up'));

const server = http.createServer(app);
const io = new Server(server, {
  cors: { origin: '*', methods: ['GET','POST'] },
  pingInterval: 10000,
  pingTimeout: 5000
});

// Optional Redis adapter for scale-out (set REDIS_URL in env)
if (process.env.REDIS_URL) {
  const pubClient = createClient({ url: process.env.REDIS_URL });
  const subClient = pubClient.duplicate();
  Promise.all([pubClient.connect(), subClient.connect()]).then(() => {
    io.adapter(createAdapter(pubClient, subClient));
    console.log('🔗 Socket.IO Redis adapter connected');
  });
}

io.on('connection', socket => {
  console.log(`🔌 Client connected: ${socket.id}`);

  // Join a session room
  socket.on('join', sessionId => {
    socket.join(sessionId);
    console.log(`${socket.id} joined ${sessionId}`);
  });

  // Relay offer
  socket.on('offer', ({ sessionId, sdp }) => {
    socket.to(sessionId).emit('offer', { sdp, from: socket.id });
  });

  // Relay answer
  socket.on('answer', ({ sessionId, sdp }) => {
    socket.to(sessionId).emit('answer', { sdp, from: socket.id });
  });

  // Relay ICE candidates
  socket.on('candidate', ({ sessionId, candidate }) => {
    socket.to(sessionId).emit('candidate', { candidate, from: socket.id });
  });

  socket.on('disconnect', reason => {
    console.log(`❌ ${socket.id} disconnected (${reason})`);
  });
});

// Start server
const PORT = process.env.PORT || 8080;
server.listen(PORT, () =>
  console.log(`🚀 Signaling server listening on port ${PORT}`)
);
