import express, { Request, Response } from 'express';
import { createServer } from 'http';
import { Server } from 'socket.io';
import cors from 'cors';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import jwt from 'jsonwebtoken';
import { startSMTPServer, inMemoryInbox } from './smtp';
import { auth as firebaseAuth } from './utils/firebaseAdmin';

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

// Define a secret key. In production, get this from process.env.JWT_SECRET
const JWT_SECRET = process.env.JWT_SECRET || 'super-secret-tempmail-key-123';

app.post('/api/auth/firebase-login', async (req: Request, res: Response) => {
    try {
        const { idToken, name } = req.body;

        if (!idToken) {
            return res.status(400).json({ error: 'ID Token is required' });
        }

        // 1. Verify the Firebase token
        let decodedToken;
        if (firebaseAuth) {
            decodedToken = await firebaseAuth.verifyIdToken(idToken);
        } else {
            // Mock mode if Firebase Admin is not fully initialized in .env
            console.warn('[Mock Mode] Firebase Admin missing config. Proceeding as if token is valid.');
            decodedToken = { uid: 'mock-uid-123', email: 'mock@example.com' };
        }

        const email = decodedToken.email;
        const uid = decodedToken.uid;

        // 2. Here you would normally lookup the user in PostgreSQL
        // if (!user) { await db.query('INSERT INTO users(uid, email, name) VALUES($1,$2,$3)', [uid, email, name]) }
        console.log(`User logged in via Firebase: ${email} (${uid})`);

        // 3. Issue our own system's JWT
        const token = jwt.sign(
            { id: uid, email: email, role: 'user' },
            JWT_SECRET,
            { expiresIn: '7d' } // keep user logged in for 7 days
        );

        res.json({
            message: 'Login successful',
            token: token,
            user: { uid, email, name }
        });
    } catch (error: any) {
        console.error('Firebase Auth Error:', error);
        res.status(401).json({ error: 'Unauthorized. Invalid Firebase Token.' });
    }
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
