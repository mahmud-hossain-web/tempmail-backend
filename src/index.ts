import express from 'express';
import { createServer } from 'http';
import { Server } from 'socket.io';
import cors from 'cors';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import { startSMTPServer, inMemoryInbox } from './smtp';

const app = express();
const httpServer = createServer(app);
export const io = new Server(httpServer, {
    cors: { origin: '*' }
});

app.use(helmet());
app.use(cors());
app.use(express.json());

const apiLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 100, // 100 requests per 15 minutes
});
app.use('/api', apiLimiter);

app.get('/api/health', (req, res) => {
    res.json({ status: 'OK', uptime: process.uptime() });
});

app.get('/api/messages/:email', (req, res) => {
    const email = (req.params.email || '').toLowerCase();
    const messages = inMemoryInbox.get(email) || [];
    res.json(messages);
});

io.on('connection', (socket) => {
    console.log('Client connected:', socket.id);

    socket.on('subscribe_inbox', (email) => {
        const safeEmail = (email || '').toLowerCase();
        socket.join(safeEmail);
        console.log(`Socket ${socket.id} subscribed to ${safeEmail}`);
    });

    socket.on('disconnect', () => {
        console.log('Client disconnected:', socket.id);
    });
});

const PORT = process.env.PORT || 5000;
httpServer.listen(PORT, () => {
    console.log(`Server API & WebSocket listening on port ${PORT}`);
    const smtpPort = process.env.SMTP_PORT ? parseInt(process.env.SMTP_PORT) : 25;
    startSMTPServer(smtpPort, io);
});
