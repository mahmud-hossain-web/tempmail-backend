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
import { exec } from 'child_process';

const resolveMx = promisify(dns.resolveMx);

const otpStore = new Map<string, { code: string, expires: number }>();

// ============================================
// IMAP auto-provisioning helper
// ============================================
function imapProvision(action: 'add' | 'del', email: string, password?: string): void {
    const cmd = action === 'add'
        ? `/usr/local/bin/tw-adduser "${email}" "${password}"` 
        : `/usr/local/bin/tw-deluser "${email}"`;
    exec(cmd, (err, stdout) => {
        if (err) {
            console.error(`[IMAP] ${action} failed for ${email}:`, err.message);
        } else {
            console.log(`[IMAP] ${action} OK for ${email}:`, stdout.trim());
        }
    });
}

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

// ============================================
// Email Client AutoConfig (Mozilla Thunderbird)
// URL: GET /mail/config-v1.1.xml?emailaddress=user@appschai.site
// ============================================
app.get('/mail/config-v1.1.xml', (req: Request, res: Response) => {
    const email = (req.query.emailaddress as string) || '%EMAILADDRESS%';
    res.set('Content-Type', 'application/xml');
    res.send(`<?xml version="1.0" encoding="UTF-8"?>
<clientConfig version="1.1">
  <emailProvider id="tempworld.org">
    <domain>appschai.site</domain>
    <domain>appschai.store</domain>
    <domain>appschai.space</domain>
    <domain>appschai.online</domain>
    <domain>appschai.website</domain>
    <domain>appschai.shop</domain>
    <domain>tempworld.org</domain>
    <displayName>TempWorld Mail</displayName>
    <displayShortName>TempWorld</displayShortName>
    <incomingServer type="imap">
      <hostname>mail.tempworld.org</hostname>
      <port>993</port>
      <socketType>SSL</socketType>
      <authentication>password-cleartext</authentication>
      <username>${email}</username>
    </incomingServer>
    <outgoingServer type="smtp">
      <hostname>mail.tempworld.org</hostname>
      <port>587</port>
      <socketType>STARTTLS</socketType>
      <authentication>password-cleartext</authentication>
      <username>${email}</username>
    </outgoingServer>
  </emailProvider>
</clientConfig>`);
});

// ============================================
// Microsoft Outlook Autodiscover
// URL: POST /autodiscover/autodiscover.xml
// ============================================
app.post('/autodiscover/autodiscover.xml', (req: Request, res: Response) => {
    res.set('Content-Type', 'application/xml');
    res.send(`<?xml version="1.0" encoding="utf-8"?>
<Autodiscover xmlns="http://schemas.microsoft.com/exchange/autodiscover/responseschema/2006">
  <Response xmlns="http://schemas.microsoft.com/exchange/autodiscover/outlook/responseschema/2006a">
    <Account>
      <AccountType>email</AccountType>
      <Action>settings</Action>
      <Protocol>
        <Type>IMAP</Type>
        <Server>mail.tempworld.org</Server>
        <Port>993</Port>
        <LoginName></LoginName>
        <DomainRequired>off</DomainRequired>
        <SPA>off</SPA>
        <SSL>on</SSL>
        <AuthRequired>on</AuthRequired>
      </Protocol>
      <Protocol>
        <Type>SMTP</Type>
        <Server>mail.tempworld.org</Server>
        <Port>587</Port>
        <LoginName></LoginName>
        <DomainRequired>off</DomainRequired>
        <SPA>off</SPA>
        <SSL>off</SSL>
        <Encryption>TLS</Encryption>
        <AuthRequired>on</AuthRequired>
      </Protocol>
    </Account>
  </Response>
</Autodiscover>`);
});

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

        // 5. Auto-forward if user has forwarding configured
        if (db) {
            try {
                // Find user by their temp/created email
                const usersSnap = await db.collection('users')
                    .where('email', '==', safeRecipient)
                    .limit(1)
                    .get();
                if (!usersSnap.empty) {
                    const userDoc = usersSnap.docs[0];
                    const fwdEmail = userDoc.data()?.settings?.forwardingEmail;
                    const fwdEnabled = userDoc.data()?.settings?.forwardingEnabled;
                    if (fwdEnabled && fwdEmail) {
                        const transporter = nodemailer.createTransport({
                            host: 'mail.tempworld.org',
                            port: 587,
                            secure: false,
                            auth: { user: 'noreply@tempworld.org', pass: process.env.SMTP_PASS || '' },
                        });
                        await transporter.sendMail({
                            from: `"TempWorld Forwarder" <noreply@tempworld.org>`,
                            to: fwdEmail,
                            subject: `[Fwd] ${messageData.subject}`,
                            text: `Forwarded from ${safeRecipient}:\n\n${messageData.body}`,
                            html: `<p><small>Forwarded from <b>${safeRecipient}</b></small></p><hr/>${messageData.body}`,
                        });
                        console.log(`📤 Forwarded email from ${safeRecipient} → ${fwdEmail}`);
                    }
                }
            } catch (fwdErr) {
                console.error('Forwarding error:', fwdErr);
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

// ============================================
// Forwarding Settings API
// ============================================
app.get('/api/forwarding/:email', async (req: Request, res: Response) => {
    try {
        const email = req.params.email.toLowerCase();
        if (!db) return res.json({ enabled: false, forwardTo: '' });
        const usersSnap = await db.collection('users').where('email', '==', email).limit(1).get();
        if (usersSnap.empty) return res.json({ enabled: false, forwardTo: '' });
        const data = usersSnap.docs[0].data();
        res.json({
            enabled: data?.settings?.forwardingEnabled || false,
            forwardTo: data?.settings?.forwardingEmail || '',
        });
    } catch (e) {
        res.status(500).json({ error: 'Server error' });
    }
});

app.post('/api/forwarding', async (req: Request, res: Response) => {
    try {
        const { email, enabled, forwardTo } = req.body;
        if (!email) return res.status(400).json({ error: 'Email required' });
        if (!db) return res.status(500).json({ error: 'DB unavailable' });
        const usersSnap = await db.collection('users').where('email', '==', email.toLowerCase()).limit(1).get();
        if (usersSnap.empty) return res.status(404).json({ error: 'User not found' });
        await usersSnap.docs[0].ref.update({
            'settings.forwardingEnabled': !!enabled,
            'settings.forwardingEmail': forwardTo || '',
        });
        res.json({ success: true });
    } catch (e) {
        res.status(500).json({ error: 'Server error' });
    }
});

// ============================================
// Own Domain — DNS Verification API
// ============================================
const resolveTxt = promisify(dns.resolveTxt);

// Generate a TXT record token for domain verification
app.post('/api/domain/init', async (req: Request, res: Response) => {
    try {
        const { domain, userEmail } = req.body;
        if (!domain || !userEmail) return res.status(400).json({ error: 'domain and userEmail required' });
        const cleanDomain = domain.toLowerCase().replace(/^https?:\/\//, '').replace(/\/$/, '');
        const token = `tempworld-verify=${Buffer.from(`${userEmail}-${cleanDomain}-${Date.now()}`).toString('base64').slice(0, 32)}`;
        if (db) {
            await db.collection('domainVerifications').doc(cleanDomain).set({
                domain: cleanDomain,
                userEmail,
                token,
                verified: false,
                createdAt: admin.firestore.FieldValue.serverTimestamp(),
            });
        }
        res.json({
            domain: cleanDomain,
            txtRecord: token,
            instructions: `Add this TXT record to your DNS:\nName: @ (or ${cleanDomain})\nType: TXT\nValue: ${token}`,
        });
    } catch (e) {
        res.status(500).json({ error: 'Server error' });
    }
});

// Verify domain by checking DNS TXT records
app.post('/api/domain/verify', async (req: Request, res: Response) => {
    try {
        const { domain } = req.body;
        if (!domain) return res.status(400).json({ error: 'domain required' });
        const cleanDomain = domain.toLowerCase().replace(/^https?:\/\//, '').replace(/\/$/, '');

        // Get expected token from DB
        if (!db) return res.status(500).json({ error: 'DB unavailable' });
        const docRef = db.collection('domainVerifications').doc(cleanDomain);
        const docSnap = await docRef.get();
        if (!docSnap.exists) return res.status(404).json({ error: 'Domain not initialized' });
        const { token } = docSnap.data()!;

        // Check DNS TXT records
        let verified = false;
        try {
            const records = await resolveTxt(cleanDomain);
            verified = records.some(r => r.join('').includes(token));
        } catch (dnsErr) {
            return res.status(400).json({ error: 'DNS lookup failed — record may not have propagated yet. Try again in a few minutes.' });
        }

        if (verified) {
            await docRef.update({ verified: true, verifiedAt: admin.firestore.FieldValue.serverTimestamp() });
            res.json({ verified: true, message: `Domain ${cleanDomain} verified successfully!` });
        } else {
            res.json({ verified: false, message: 'TXT record not found yet. DNS propagation can take up to 48 hours.' });
        }
    } catch (e) {
        res.status(500).json({ error: 'Server error' });
    }
});

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
                // Update IMAP password too
                imapProvision('add', email, newPassword);
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
        let decodedToken: any;
        if (firebaseAuth) {
            decodedToken = await firebaseAuth.verifyIdToken(idToken);
        } else {
            console.warn('[Mock Mode] Firebase Admin missing config. Proceeding as if token is valid.');
            decodedToken = { uid: 'mock-uid-123', email: 'mock@example.com' };
        }

        const email = decodedToken.email;
        const uid = decodedToken.uid;

        // 2. Check expiry / create new user doc
        if (db) {
            try {
                const docRef = db.collection('users').doc(uid);
                const doc = await docRef.get();

                if (doc.exists) {
                    // --- Existing user: check 31-day expiry ---
                    const userData = doc.data()!;
                    const expiresAt: Date | null = userData.expiresAt?.toDate?.() || null;

                    if (expiresAt && new Date() > expiresAt) {
                        // Account has expired → auto-delete everything
                        console.log(`[Auth] Account expired for ${email} — auto-deleting`);
                        try { await docRef.delete(); } catch (_) {}
                        try { if (firebaseAuth) await firebaseAuth.deleteUser(uid); } catch (_) {}
                        return res.status(403).json({
                            error: 'account_expired',
                            message: 'আপনার account-এর 60 দিনের মেয়াদ শেষ হয়েছে। নতুন account তৈরি করুন।'
                        });
                    }
                } else {
                    // --- New user: create with 60-day expiry ---
                    const expiresAt = new Date(Date.now() + 60 * 24 * 60 * 60 * 1000);
                    await docRef.set({
                        uid, email, name,
                        createdAt: new Date(),
                        plan: 'free',
                        expiresAt,
                    });
                    console.log(`[Auth] New user created: ${email}, expires: ${expiresAt.toISOString()}`);
                }
            } catch (error) {
                console.error('Firebase DB error during login:', error);
            }
        }

        console.log(`User logged in via Firebase: ${email} (${uid})`);

        // 3. Read user doc to get plan/expiresAt for response
        let userDoc: any = { plan: 'free', expiresAt: null };
        if (db) {
            try {
                const snap = await db.collection('users').doc(uid).get();
                if (snap.exists) userDoc = snap.data();
            } catch (_) {}
        }

        // 4. Issue JWT valid for 60 days (matches account lifetime)
        const token = jwt.sign(
            { id: uid, email: email, role: 'user' },
            JWT_SECRET,
            { expiresIn: '60d' }
        );

        res.json({
            message: 'Login successful',
            token: token,
            user: {
                uid, email, name,
                plan: userDoc.plan || 'free',
                expiresAt: userDoc.expiresAt?.toDate?.()?.toISOString() || null,
            }
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

// ============================================
// Update IMAP password (called after Firebase password change)
// ============================================
app.post('/api/auth/update-imap-password', async (req: Request, res: Response) => {
    try {
        const authHeader = req.headers['authorization'] || '';
        const idToken = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : null;
        if (!idToken) return res.status(401).json({ error: 'Unauthorized' });

        const decoded = await admin.auth().verifyIdToken(idToken);
        const { newPassword } = req.body;
        if (!newPassword || !decoded.email) return res.status(400).json({ error: 'Missing password or email' });

        imapProvision('add', decoded.email, newPassword);
        res.json({ success: true });
    } catch (err: any) {
        res.status(500).json({ error: err.message });
    }
});

// ============================================
// Delete Account (no re-login required)
// ============================================
app.delete('/api/auth/delete-account', async (req: Request, res: Response) => {
    try {
        const authHeader = req.headers['authorization'] || '';
        const idToken = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : null;
        if (!idToken) return res.status(401).json({ error: 'Unauthorized' });

        // Verify the Firebase ID token
        const decoded = await admin.auth().verifyIdToken(idToken);
        const uid = decoded.uid;

        // Delete from Firestore user record if it exists
        try {
            await admin.firestore().collection('users').doc(uid).delete();
        } catch (_) {}

        // Delete from Firebase Auth using Admin SDK (no re-login needed)
        await admin.auth().deleteUser(uid);

        // Remove IMAP mailbox
        const userEmail = decoded.email || '';
        if (userEmail) imapProvision('del', userEmail);

        res.json({ success: true });
    } catch (err: any) {
        console.error('Delete account error:', err);
        res.status(500).json({ error: err.message || 'Failed to delete account' });
    }
});

// ============================================
// Send Email from Registered Account
// ============================================
app.post('/api/send-email', async (req: Request, res: Response) => {

    try {
        // 1. Verify JWT
        const authHeader = req.headers['authorization'] || '';
        const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : null;
        if (!token) return res.status(401).json({ error: 'Unauthorized: No token provided' });

        let decoded: any;
        try {
            decoded = jwt.verify(token, JWT_SECRET);
        } catch {
            return res.status(401).json({ error: 'Unauthorized: Invalid token' });
        }

        const fromEmail = (decoded.email || '').toLowerCase();
        if (!fromEmail) return res.status(400).json({ error: 'No email in token' });

        const { to, subject, body } = req.body;
        if (!to || !subject || !body) {
            return res.status(400).json({ error: 'to, subject, and body are required' });
        }

        const toEmail = (to || '').toLowerCase();

        // 2. Deliver the email to the recipient via SMTP
        try {
            const domain = toEmail.split('@')[1];
            const mxRecords = await resolveMx(domain);
            mxRecords.sort((a, b) => a.priority - b.priority);

            const transporter = nodemailer.createTransport({
                host: mxRecords[0].exchange,
                port: 25,
                secure: false,
                name: fromEmail.split('@')[1] || 'tempworld.org',
                tls: { rejectUnauthorized: false },
                connectionTimeout: 10000,
                greetingTimeout: 10000,
                dkim: dkimPrivateKey ? {
                    domainName: fromEmail.split('@')[1] || 'tempworld.org',
                    keySelector: 'mail',
                    privateKey: dkimPrivateKey,
                } : undefined,
            });

            await transporter.sendMail({
                from: `"${decoded.name || fromEmail.split('@')[0]}" <${fromEmail}>`,
                to: toEmail,
                subject,
                text: body,
                html: `<div style="font-family:Arial,sans-serif;white-space:pre-wrap">${body.replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/\n/g,'<br>')}</div>`,
            });
        } catch (smtpErr) {
            console.error('SMTP send error:', smtpErr);
            // Continue — still store in local inbox if recipient is internal
        }

        // 3. If recipient is a TempWorld domain address, inject directly into their inbox
        const INTERNAL_DOMAINS = [
            'appschai.site', 'appschai.store', 'appschai.space', 'appschai.online',
            'appschai.website', 'appschai.shop', 'appschai.fun', 'appschai.sbs',
            'tempworld.org', 'temp-mail.my', 'trustbro.shop', 'trustbro.space',
            'trustbro.online', 'trustbro.site', 'makeu3.store', 'mahmud.shop', 'mahmud.sbs',
        ];
        const recipientDomain = toEmail.split('@')[1] || '';
        if (INTERNAL_DOMAINS.includes(recipientDomain)) {
            const uniqueId = Date.now().toString() + '_' + Math.random().toString(36).substring(2, 8);
            const messageData = {
                id: uniqueId,
                sender: fromEmail,
                subject: subject || 'No Subject',
                time: new Date().toLocaleTimeString(),
                body: body || '',
            };

            // Emit to recipient's socket room
            io.to(toEmail).emit('new_email', messageData);

            // Save in memory
            const cur = inMemoryInbox.get(toEmail) || [];
            inMemoryInbox.set(toEmail, [messageData, ...cur]);

            // Save to Firestore
            if (db) {
                try {
                    await db.collection('messages').doc(messageData.id).set({
                        ...messageData,
                        recipient: toEmail,
                        timestamp: admin.firestore.FieldValue.serverTimestamp(),
                    });
                } catch (e) {
                    console.error('Firestore error saving sent message:', e);
                }
            }

            // Save to Redis
            if (redisClient.isOpen) {
                try {
                    await redisClient.lPush(`inbox:${toEmail}`, JSON.stringify(messageData));
                } catch (e) {
                    console.error('Redis error saving sent message:', e);
                }
            }
        }

        console.log(`📤 Email sent from ${fromEmail} to ${toEmail}`);
        res.json({ success: true, message: 'Email sent successfully' });

    } catch (error) {
        console.error('Send email error:', error);
        res.status(500).json({ error: 'Failed to send email' });
    }
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

// ============================================
// PAYMENT SYSTEM
// ============================================

// JWT auth middleware (reused for payment routes)
async function requireAuth(req: Request, res: Response, next: any) {
    const authHeader = req.headers['authorization'] || '';
    const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : null;
    if (!token) return res.status(401).json({ error: 'Unauthorized' });
    
    // Try 1: Verify as our custom JWT
    try {
        const decoded = jwt.verify(token, JWT_SECRET) as any;
        (req as any).user = decoded;
        return next();
    } catch (_) {
        // Not a custom JWT, try Firebase ID token
    }
    
    // Try 2: Verify as Firebase ID token
    if (firebaseAuth) {
        try {
            const decodedFirebase = await firebaseAuth.verifyIdToken(token);
            const uid = decodedFirebase.uid;
            const email = decodedFirebase.email || '';
            
            // Auto-create user document in Firestore if not exists
            if (db) {
                try {
                    const userRef = db.collection('users').doc(uid);
                    const userSnap = await userRef.get();
                    if (!userSnap.exists) {
                        await userRef.set({ uid, email, createdAt: new Date(), plan: 'free', mailCredits: 0 });
                        console.log(`[requireAuth] Auto-created user doc for ${email} (${uid})`);
                    }
                } catch (e) { console.warn('[requireAuth] Could not auto-create user doc:', e); }
            }
            
            (req as any).user = { id: uid, email, role: 'user' };
            return next();
        } catch (firebaseErr) {
            console.warn('[requireAuth] Firebase token verify failed:', (firebaseErr as any).message);
        }
    }
    
    return res.status(401).json({ error: 'Invalid token' });
}


function requireAdmin(req: Request, res: Response, next: any) {
    const authHeader = req.headers['authorization'] || '';
    const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : null;
    if (!token) return res.status(401).json({ error: 'Unauthorized' });
    try {
        const decoded: any = jwt.verify(token, JWT_SECRET);
        if (decoded.role !== 'admin') return res.status(403).json({ error: 'Forbidden' });
        (req as any).user = decoded;
        next();
    } catch {
        return res.status(401).json({ error: 'Invalid token' });
    }
}

// POST /api/payment/submit — Customer submits a payment request
app.post('/api/payment/submit', requireAuth, async (req: Request, res: Response) => {
    try {
        const user = (req as any).user;
        const { planType, planKey, mailCount, amount, currency, paymentMethod, txId } = req.body;
        // planType: 'created_mail' | 'subscription'
        // planKey: 'created-10' | 'created-50' | 'created-100' | 'lite' | 'pro' | 'ultra'

        if (!planType || !txId || !paymentMethod || !amount) {
            return res.status(400).json({ error: 'Missing required fields' });
        }

        if (!db) return res.status(500).json({ error: 'DB not available' });

        const paymentRef = db.collection('paymentRequests').doc();
        await paymentRef.set({
            id: paymentRef.id,
            userId: user.id,
            userEmail: user.email,
            planType,           // 'created_mail' or 'subscription'
            planKey,            // e.g. 'created-10', 'pro'
            mailCount: mailCount || 0,
            amount,
            currency: currency || 'BDT',
            paymentMethod,
            txId,
            status: 'pending',
            submittedAt: admin.firestore.FieldValue.serverTimestamp(),
        });

        console.log(`💳 Payment submitted: ${user.email} | ${planKey} | ${currency} ${amount} | txId: ${txId}`);
        res.json({ success: true, message: 'Payment request submitted. Activation within 1-2 hours.' });
    } catch (err: any) {
        console.error('Payment submit error:', err);
        res.status(500).json({ error: err.message });
    }
});

// GET /api/payment/pending — Admin fetches pending payments
app.get('/api/payment/pending', requireAdmin, async (req: Request, res: Response) => {
    try {
        if (!db) return res.status(500).json({ error: 'DB not available' });
        const snap = await db.collection('paymentRequests')
            .orderBy('submittedAt', 'desc')
            .limit(100)
            .get();
        const payments = snap.docs.map(d => ({ id: d.id, ...d.data() }));
        res.json(payments);
    } catch (err: any) {
        res.status(500).json({ error: err.message });
    }
});

// POST /api/payment/approve — Admin approves or rejects a payment
app.post('/api/payment/approve', requireAdmin, async (req: Request, res: Response) => {
    try {
        const { paymentId, action } = req.body; // action: 'approve' | 'reject'
        if (!paymentId || !action) return res.status(400).json({ error: 'Missing paymentId or action' });
        if (!db) return res.status(500).json({ error: 'DB not available' });

        const payRef = db.collection('paymentRequests').doc(paymentId);
        const paySnap = await payRef.get();
        if (!paySnap.exists) return res.status(404).json({ error: 'Payment not found' });

        const payment = paySnap.data()!;

        if (action === 'reject') {
            await payRef.update({ status: 'rejected', reviewedAt: admin.firestore.FieldValue.serverTimestamp() });
            return res.json({ success: true, message: 'Payment rejected' });
        }

        // APPROVE
        const userRef = db.collection('users').doc(payment.userId);

        if (payment.planType === 'created_mail') {
            // Add mail credits to user
            await userRef.set({
                mailCredits: admin.firestore.FieldValue.increment(payment.mailCount),
            }, { merge: true });

        } else if (payment.planType === 'subscription') {
            // Activate subscription
            const planDurations: Record<string, number> = { lite: 30, pro: 30, ultra: 30 };
            const days = planDurations[payment.planKey] || 30;
            const expiresAt = new Date(Date.now() + days * 24 * 60 * 60 * 1000);
            await userRef.set({
                plan: payment.planKey,
                subscriptionExpiresAt: expiresAt,
            }, { merge: true });
        }

        await payRef.update({ status: 'approved', reviewedAt: admin.firestore.FieldValue.serverTimestamp() });

        console.log(`✅ Payment approved: ${payment.userEmail} | ${payment.planKey}`);
        res.json({ success: true, message: 'Payment approved and plan activated' });
    } catch (err: any) {
        console.error('Payment approve error:', err);
        res.status(500).json({ error: err.message });
    }
});

// ============================================
// CREATED MAIL MANAGEMENT
// ============================================

// POST /api/mail/create — Create a new mail (deducts 1 credit)
app.post('/api/mail/create', requireAuth, async (req: Request, res: Response) => {
    try {
        const user = (req as any).user;
        const { mailName, domain } = req.body;
        if (!mailName || !domain) return res.status(400).json({ error: 'mailName and domain are required' });
        if (!db) return res.status(500).json({ error: 'DB not available' });

        // Check credits
        const userSnap = await db.collection('users').doc(user.id).get();
        if (!userSnap.exists) return res.status(404).json({ error: 'User not found' });
        const userData = userSnap.data()!;
        const credits = userData.mailCredits || 0;
        if (credits < 1) return res.status(403).json({ error: 'No mail credits. Please purchase a Created Mail plan.' });

        const email = `${mailName.toLowerCase().replace(/[^a-z0-9._-]/g, '')}@${domain}`;
        const expiresAt = new Date(Date.now() + 31 * 24 * 60 * 60 * 1000);
        const password = (() => { const u='ABCDEFGHJKLMNPQRSTUVWXYZ',l='abcdefghjkmnpqrstuvwxyz',n='23456789'; const all=u+l+n; let p=u[Math.floor(Math.random()*u.length)]+l[Math.floor(Math.random()*l.length)]+n[Math.floor(Math.random()*n.length)]; for(let i=3;i<8;i++) p+=all[Math.floor(Math.random()*all.length)]; return p.split('').sort(()=>Math.random()-0.5).join(''); })(); // 8-char mixed password

        // Create mail record in Firestore  
        const mailRef = db.collection('createdMails').doc();
        await mailRef.set({
            id: mailRef.id,
            userId: user.id,
            userEmail: user.email,
            email,
            domain,
            password,
            createdAt: admin.firestore.FieldValue.serverTimestamp(),
            expiresAt,
            status: 'active',
        });

        // Deduct 1 credit
        await db.collection('users').doc(user.id).update({
            mailCredits: admin.firestore.FieldValue.increment(-1),
        });

        // Provision IMAP mailbox
        imapProvision('add', email, password);

        console.log(`📧 Created mail: ${email} for ${user.email} (expires ${expiresAt.toISOString()})`);
        res.json({ success: true, email, password, expiresAt: expiresAt.toISOString() });
    } catch (err: any) {
        console.error('Mail create error:', err);
        res.status(500).json({ error: err.message });
    }
});

// GET /api/mail/list — List user's created mails
app.get('/api/mail/list', requireAuth, async (req: Request, res: Response) => {
    try {
        const user = (req as any).user;
        if (!db) return res.status(500).json({ error: 'DB not available' });

        // First get credits — this always works
        const userSnap = await db.collection('users').doc(user.id).get();
        const credits = userSnap.exists ? (userSnap.data()!.mailCredits || 0) : 0;

        // Try to get mails — use simple query without orderBy to avoid composite index requirement
        let mails: any[] = [];
        try {
            const snap = await db.collection('createdMails')
                .where('userId', '==', user.id)
                .get();

            mails = snap.docs.map(d => {
                const data = d.data();
                return {
                    id: d.id,
                    email: data.email,
                    password: data.password,
                    expiresAt: data.expiresAt?.toDate?.()?.toISOString() || null,
                    status: data.status,
                    createdAt: data.createdAt?.toDate?.()?.toISOString() || null,
                };
            });
            // Sort by createdAt descending in JS (no Firestore index needed)
            mails.sort((a, b) => {
                if (!a.createdAt) return 1;
                if (!b.createdAt) return -1;
                return new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime();
            });
        } catch (mailErr: any) {
            console.warn('[mail/list] Could not fetch mails (index missing?), returning credits only:', mailErr.message);
        }

        res.json({ credits, mails });
    } catch (err: any) {
        res.status(500).json({ error: err.message });
    }
});

// DELETE /api/mail/:mailId — Delete a created mail
app.delete('/api/mail/:mailId', requireAuth, async (req: Request, res: Response) => {
    try {
        const user = (req as any).user;
        if (!db) return res.status(500).json({ error: 'DB not available' });

        const mailRef = db.collection('createdMails').doc(req.params.mailId);
        const mailSnap = await mailRef.get();
        if (!mailSnap.exists) return res.status(404).json({ error: 'Mail not found' });

        const mailData = mailSnap.data()!;
        if (mailData.userId !== user.id) return res.status(403).json({ error: 'Forbidden' });

        // Delete IMAP mailbox
        imapProvision('del', mailData.email);
        await mailRef.update({ status: 'deleted', deletedAt: admin.firestore.FieldValue.serverTimestamp() });

        res.json({ success: true });
    } catch (err: any) {
        res.status(500).json({ error: err.message });
    }
});

// GET /api/user/profile — Get user plan, credits, subscription
app.get('/api/user/profile', requireAuth, async (req: Request, res: Response) => {
    try {
        const user = (req as any).user;
        if (!db) return res.status(500).json({ error: 'DB not available' });

        const snap = await db.collection('users').doc(user.id).get();
        if (!snap.exists) return res.status(404).json({ error: 'User not found' });

        const data = snap.data()!;
        res.json({
            plan: data.plan || 'free',
            mailCredits: data.mailCredits || 0,
            subscriptionExpiresAt: data.subscriptionExpiresAt?.toDate?.()?.toISOString() || null,
            expiresAt: data.expiresAt?.toDate?.()?.toISOString() || null,
        });
    } catch (err: any) {
        res.status(500).json({ error: err.message });
    }
});

// ============================================
// Socket.io real-time inbox
// ============================================
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

// ============================================
// CRON JOB: Inbox lifetime management
//  - Email messages auto-delete: 2 hours
//  - Inactive inbox cleanup: 24 hours
// Runs every 30 minutes
// ============================================
async function runEmailCleanup() {
    const now = Date.now();
    const EMAIL_TTL_MS = 2 * 60 * 60 * 1000;   // 2 hours
    const emailCutoff = new Date(now - EMAIL_TTL_MS);

    console.log(`🧹 [Cleanup] Deleting emails before ${emailCutoff.toISOString()}`);
    let totalDeleted = 0;

    // 1. Delete messages older than 2 hours from Firestore
    if (db) {
        try {
            let hasMore = true;
            while (hasMore) {
                const snapshot = await db.collection('messages')
                    .where('timestamp', '<', emailCutoff)
                    .limit(100)
                    .get();

                if (snapshot.empty) { hasMore = false; break; }

                const batch = db.batch();
                snapshot.docs.forEach(doc => batch.delete(doc.ref));
                await batch.commit();
                totalDeleted += snapshot.size;

                if (snapshot.size < 100) hasMore = false;
            }
        } catch (err) {
            console.error('🧹 [Cleanup] Firestore error:', err);
        }
    }

    // 2. Clear in-memory inboxes (session-based, cleared every cycle)
    const inboxCount = inMemoryInbox.size;
    inMemoryInbox.clear();

    // 3. Clear stale Redis inbox keys
    if (redisClient.isOpen) {
        try {
            const keys = await redisClient.keys('inbox:*');
            if (keys.length > 0) {
                await redisClient.del(keys);
            }
        } catch (err) {
            console.error('🧹 [Cleanup] Redis error:', err);
        }
    }

    // 4. Delete expired accounts (31-day limit)
    if (db && firebaseAuth) {
        try {
            const expiredSnapshot = await db.collection('users')
                .where('expiresAt', '<', new Date())
                .limit(50)
                .get();

            for (const docSnap of expiredSnapshot.docs) {
                const userData = docSnap.data();
                try {
                    // Delete from Firebase Auth
                    if (userData.uid) await firebaseAuth.deleteUser(userData.uid);
                    // Delete user messages
                    if (userData.email) {
                        const msgs = await db.collection('messages').where('recipient', '==', userData.email).limit(200).get();
                        const batch = db.batch();
                        msgs.docs.forEach(m => batch.delete(m.ref));
                        await batch.commit();
                    }
                    // Delete user doc
                    await docSnap.ref.delete();
                    console.log(`🗑️ [Cleanup] Deleted expired account: ${userData.email}`);
                } catch (e) {
                    console.error(`[Cleanup] Failed to delete account ${userData.uid}:`, e);
                }
            }
        } catch (err) {
            console.error('🧹 [Cleanup] Account expiry error:', err);
        }
    }

    console.log(`✅ [Cleanup] Done. Firestore deleted: ${totalDeleted}, in-memory cleared: ${inboxCount}`);
    return totalDeleted;
}

// Run cleanup every 30 minutes (starts 1 minute after server boot)
function startCleanupScheduler() {
    console.log('⏰ [Cleanup] Scheduler started — runs every 30 minutes (2h email TTL, 24h inactive inbox TTL)');
    setTimeout(() => {
        runEmailCleanup();
        setInterval(runEmailCleanup, 30 * 60 * 1000);
    }, 60 * 1000);
}

const PORT = process.env.PORT || 5000;
httpServer.listen(PORT, () => {
    console.log(`Server API & WebSocket listening on port ${PORT}`);
    const smtpPort = process.env.SMTP_PORT ? parseInt(process.env.SMTP_PORT) : 25;
    startSMTPServer(smtpPort, io);
    startCleanupScheduler();
});
