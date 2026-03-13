import express, { Request, Response } from 'express';
import { createServer } from 'http';
import { Server } from 'socket.io';
import cors from 'cors';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import jwt from 'jsonwebtoken';
import { startSMTPServer, inMemoryInbox } from './smtp';
import { auth as firebaseAuth, db } from './utils/firebaseAdmin';
import * as admin from 'firebase-admin';
import redisClient from './redis';
import adminRoutes from './routes/admin';
import nodemailer from 'nodemailer';
import dns from 'dns';
import { promisify } from 'util';
import fs from 'fs';
import path from 'path';

const resolveMx = promisify(dns.resolveMx);

const otpStore = new Map<string, { code: string, expires: number }>();

// Load DKIM private key
let dkimPrivateKey = '';
try {
    dkimPrivateKey = fs.readFileSync('/etc/dkim/tempworld.key', 'utf8');
    console.log('DKIM private key loaded successfully');
} catch (e) {
    console.warn('DKIM private key not found, emails may not be delivered');
}

// Send email directly to recipient's MX server with DKIM signing
async function sendOtpEmail(to: string, subject: string, text: string, html: string) {
    const domain = to.split('@')[1];
    const mxRecords = await resolveMx(domain);
    mxRecords.sort((a, b) => a.priority - b.priority);
    
    const transporter = nodemailer.createTransport({
        host: mxRecords[0].exchange,
        port: 25,
        secure: false,
        name: 'tempworld.org',
        tls: { rejectUnauthorized: false },
        connectionTimeout: 10000,
        greetingTimeout: 10000,
        dkim: dkimPrivateKey ? {
            domainName: 'tempworld.org',
            keySelector: 'mail',
            privateKey: dkimPrivateKey,
        } : undefined,
    });

    await transporter.sendMail({
        from: '"TempWorld" <noreply@tempworld.org>',
        to,
        subject,
        text,
        html,
    });
}

const WORKER_SECRET = process.env.WORKER_SECRET || 'your-secret-key';

const app = express();
app.set('trust proxy', 1); // Trust first proxy (Nginx)
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

// Admin dashboard API routes
app.use('/api/admin', adminRoutes);

// Mock API Key Middleware for Developers
const developerApiAuth = (req: Request, res: Response, next: any) => {
    const apiKey = req.headers['x-api-key'];
    if (!apiKey) {
        return res.status(401).json({ error: 'Unauthorized: Missing x-api-key header' });
    }
    // In production, validate this against the DB for premium users
    if (apiKey !== 'test_developer_key' && apiKey.length < 10) {
        return res.status(401).json({ error: 'Unauthorized: Invalid API Key' });
    }
    next();
};

app.get('/api/health', (req, res) => {
    res.json({ status: 'OK', uptime: process.uptime() });
});

// ============================================
// Cloudflare Email Worker - Incoming Email
// ============================================
app.post('/api/incoming-email', async (req: Request, res: Response) => {
    try {
        // 1. Verify the worker secret
        const secret = req.headers['x-worker-secret'];
        if (secret !== WORKER_SECRET) {
            console.warn('Unauthorized incoming email attempt');
            return res.status(401).json({ error: 'Unauthorized' });
        }

        const { recipient, sender, subject, body, receivedAt } = req.body;

        if (!recipient) {
            return res.status(400).json({ error: 'Recipient is required' });
        }

        const safeRecipient = (recipient || '').toLowerCase();
        console.log(`📩 Incoming email from Cloudflare Worker for: ${safeRecipient}`);

        const uniqueId = Date.now().toString() + '_' + Math.random().toString(36).substring(2, 8);
        const messageData = {
            id: uniqueId,
            sender: sender || 'Unknown',
            subject: subject || 'No Subject',
            time: new Date(receivedAt || Date.now()).toLocaleTimeString(),
            body: body || '',
        };

        // 2. Emit via Socket.io for real-time inbox
        io.to(safeRecipient).emit('new_email', messageData);

        // 3. Save in memory
        const currentMessages = inMemoryInbox.get(safeRecipient) || [];
        inMemoryInbox.set(safeRecipient, [messageData, ...currentMessages]);

        // 4. Save to Firebase
        if (db) {
            try {
                const docRef = db.collection('messages').doc(messageData.id);
                await docRef.set({
                    ...messageData,
                    recipient: safeRecipient,
                    timestamp: admin.firestore.FieldValue.serverTimestamp()
                });
            } catch (error) {
                console.error('Firebase DB error saving email:', error);
            }
        }

        // 5. Cache to Redis
        if (redisClient.isOpen) {
            try {
                await redisClient.lPush(`inbox:${safeRecipient}`, JSON.stringify(messageData));
            } catch (err) {
                console.error('Redis Error saving email:', err);
            }
        }

        console.log(`✅ Email processed successfully for ${safeRecipient}`);
        res.json({ success: true, message: 'Email received and processed' });

    } catch (error) {
        console.error('Error processing incoming email:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Define a secret key. In production, get this from process.env.JWT_SECRET
const JWT_SECRET = process.env.JWT_SECRET || 'super-secret-tempmail-key-123';

app.post('/api/auth/send-otp', async (req: Request, res: Response) => {
    try {
        const { email } = req.body;
        if (!email) return res.status(400).json({ error: 'Email is required' });

        const code = Math.floor(100000 + Math.random() * 900000).toString();
        // 10 minute expiry
        otpStore.set(email.toLowerCase(), { code, expires: Date.now() + 10 * 60 * 1000 });

        await sendOtpEmail(
            email,
            'Your TempWorld Verification Code',
            `Your verification code is: ${code}\nIt will expire in 10 minutes.`,
            `<div style="font-family:Arial,sans-serif;max-width:400px;margin:0 auto;padding:20px;background:#0f172a;border-radius:12px;color:#e2e8f0">
                <h2 style="text-align:center;color:#818cf8">TempWorld</h2>
                <p style="text-align:center;font-size:14px;color:#94a3b8">Your verification code is:</p>
                <div style="text-align:center;font-size:32px;font-weight:bold;letter-spacing:8px;color:#ffffff;padding:16px;background:#1e293b;border-radius:8px;margin:16px 0">${code}</div>
                <p style="text-align:center;font-size:12px;color:#64748b">This code expires in 10 minutes.</p>
            </div>`
        );
        res.json({ message: 'OTP sent successfully' });
    } catch (err) {
        console.error('OTP processing error:', err);
        res.status(500).json({ error: 'Internal server error' });
    }
});

app.post('/api/auth/verify-otp', async (req: Request, res: Response) => {
    try {
        const { email, code } = req.body;
        if (!email || !code) return res.status(400).json({ error: 'Email and code are required' });

        const storedOtp = otpStore.get(email.toLowerCase());
        if (!storedOtp) return res.status(400).json({ error: 'No OTP found for this email. Please resend.' });

        if (Date.now() > storedOtp.expires) {
            otpStore.delete(email.toLowerCase());
            return res.status(400).json({ error: 'OTP has expired. Please request a new one.' });
        }

        if (storedOtp.code !== code) {
            return res.status(400).json({ error: 'Invalid OTP code' });
        }

        // Clean up
        otpStore.delete(email.toLowerCase());

        // Update Firebase User
        if (firebaseAuth) {
            try {
                const userRecord = await firebaseAuth.getUserByEmail(email);
                if (!userRecord.emailVerified) {
                    await firebaseAuth.updateUser(userRecord.uid, { emailVerified: true });
                }
            } catch (fbErr) {
                console.error('Firebase update error during OTP verification:', fbErr);
                // Continue anyway, maybe they don't have a Firebase account yet
            }
        }

        res.json({ message: 'Email verified successfully' });
    } catch (err) {
        console.error('OTP verification error:', err);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Reset password with OTP verification
app.post('/api/auth/reset-password-otp', async (req: Request, res: Response) => {
    try {
        const { email, code, newPassword } = req.body;
        if (!email || !code || !newPassword) {
            return res.status(400).json({ error: 'Email, code, and new password are required' });
        }

        if (newPassword.length < 6) {
            return res.status(400).json({ error: 'Password must be at least 6 characters' });
        }

        const stored = otpStore.get(email);
        if (!stored) return res.status(400).json({ error: 'No OTP found. Please request a new code.' });
        if (Date.now() > stored.expires) {
            otpStore.delete(email);
            return res.status(400).json({ error: 'OTP expired. Please request a new code.' });
        }
        if (stored.code !== code) return res.status(400).json({ error: 'Invalid OTP code' });

        // OTP verified, now reset password
        otpStore.delete(email);

        if (firebaseAuth) {
            try {
                const userRecord = await firebaseAuth.getUserByEmail(email);
                await firebaseAuth.updateUser(userRecord.uid, { password: newPassword });
            } catch (fbErr) {
                console.error('Firebase password reset error:', fbErr);
                return res.status(500).json({ error: 'Failed to reset password' });
            }
        }

        res.json({ message: 'Password reset successfully' });
    } catch (err) {
        console.error('Password reset error:', err);
        res.status(500).json({ error: 'Internal server error' });
    }
});

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
        if (db) {
            try {
                const docRef = db.collection('users').doc(uid);
                const doc = await docRef.get();
                if (!doc.exists) {
                    await docRef.set({
                        uid, email, name, createdAt: new Date()
                    });
                }
            } catch (error) {
                console.error("Firebase DB error saving user", error);
            }
        }
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

app.get('/api/messages/:email', async (req, res) => {
    const email = (req.params.email || '').toLowerCase();

    if (db) {
        try {
            const snapshot = await db.collection('messages')
                .where('recipient', '==', email)
                .orderBy('timestamp', 'desc')
                .get();

            if (!snapshot.empty) {
                const messages = snapshot.docs.map(doc => {
                    const data = doc.data();
                    // Don't send internal timestamp to client if it fails
                    delete data.timestamp;
                    return data;
                });
                return res.json(messages);
            }
        } catch (error) {
            console.error("Firebase DB Error fetching messages:", error);
        }
    }

    const messages = inMemoryInbox.get(email) || [];
    res.json(messages);
});

// Developer API Endpoints
app.get('/api/developer/domains', developerApiAuth, (req, res) => {
    res.json({
        domains: ["appschai.site", "appschai.store", "appschai.space", "appschai.online", "appschai.website", "appschai.shop", "appschai.fun", "appschai.sbs"]
    });
});

app.post('/api/developer/generate', developerApiAuth, (req, res) => {
    const { domain } = req.body;
    const selectedDomain = domain || "appschai.site";
    const randomStr = Math.random().toString(36).substring(2, 10);
    res.json({ email: `${randomStr}@${selectedDomain}` });
});

app.get('/api/developer/messages/:email', developerApiAuth, async (req, res) => {
    const email = (req.params.email || '').toLowerCase();

    if (db) {
        try {
            const snapshot = await db.collection('messages')
                .where('recipient', '==', email)
                .orderBy('timestamp', 'desc')
                .get();

            if (!snapshot.empty) {
                const messages = snapshot.docs.map(doc => {
                    const data = doc.data();
                    delete data.timestamp;
                    return data;
                });
                return res.json({ count: messages.length, messages });
            }
        } catch (error) {
            console.error("Firebase DB Error fetching developer messages:", error);
        }
    }

    const messages = inMemoryInbox.get(email) || [];
    res.json({ count: messages.length, messages: messages });
});

app.delete('/api/developer/messages/:email', developerApiAuth, async (req, res) => {
    const email = (req.params.email || '').toLowerCase();
    inMemoryInbox.set(email, []);

    if (db) {
        try {
            const snapshot = await db.collection('messages')
                .where('recipient', '==', email)
                .get();

            const batch = db.batch();
            snapshot.docs.forEach((doc) => {
                batch.delete(doc.ref);
            });
            await batch.commit();
        } catch (error) {
            console.error("Firebase DB Error deleting developer messages:", error);
        }
    }

    res.json({ success: true, message: 'Inbox cleared' });
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
