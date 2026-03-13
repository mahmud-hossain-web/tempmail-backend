import { Router, Request, Response } from 'express';
import { adminAuthOrDev, AdminRequest } from '../middlewares/adminAuth';
import { db } from '../utils/firebaseAdmin';
import redisClient from '../redis';
import { inMemoryInbox } from '../smtp';

const router = Router();

// Apply admin auth middleware to all routes
router.use(adminAuthOrDev as any);

// ═══════════════════════════════════════════════
//  DASHBOARD OVERVIEW
// ═══════════════════════════════════════════════

router.get('/stats', async (req: AdminRequest, res: Response) => {
    try {
        let totalUsers = 0, totalEmails = 0, totalDomains = 15;
        let emailsToday = 0, activeAddresses = 0, spamBlocked = 0;

        // Get user count from Firebase
        if (db) {
            try {
                const usersSnapshot = await db.collection('users').count().get();
                totalUsers = usersSnapshot.data().count;
            } catch (e) { totalUsers = 0; }

            try {
                const today = new Date();
                today.setHours(0, 0, 0, 0);
                const messagesSnapshot = await db.collection('messages')
                    .where('timestamp', '>=', today)
                    .count().get();
                emailsToday = messagesSnapshot.data().count;
            } catch (e) { emailsToday = 0; }

            try {
                const allMsgSnapshot = await db.collection('messages').count().get();
                totalEmails = allMsgSnapshot.data().count;
            } catch (e) { totalEmails = 0; }
        }

        // Get active addresses from in-memory inbox
        activeAddresses = inMemoryInbox.size;

        // Get cached stats from Redis
        if (redisClient.isOpen) {
            try {
                const cached = await redisClient.get('admin:spam_blocked_today');
                spamBlocked = cached ? parseInt(cached) : 0;
            } catch (e) { }
        }

        // Server health
        const uptime = process.uptime();
        const memUsage = process.memoryUsage();

        res.json({
            overview: {
                totalUsers,
                totalEmails,
                emailsToday,
                activeAddresses,
                totalDomains,
                spamBlocked,
                revenue: 0, // Will integrate with payment system
            },
            server: {
                uptime: Math.floor(uptime),
                memoryUsed: Math.round(memUsage.heapUsed / 1024 / 1024),
                memoryTotal: Math.round(memUsage.heapTotal / 1024 / 1024),
                cpuUsage: 0,
                nodeVersion: process.version,
            },
            health: {
                api: { status: 'operational', latency: 12 },
                smtp: { status: 'operational', latency: 8 },
                firebase: { status: db ? 'operational' : 'disconnected', latency: db ? 45 : 0 },
                redis: { status: redisClient.isOpen ? 'operational' : 'disconnected', latency: redisClient.isOpen ? 3 : 0 },
                websocket: { status: 'operational', latency: 15 },
            },
        });
    } catch (error) {
        console.error('Admin stats error:', error);
        res.status(500).json({ error: 'Failed to fetch dashboard stats' });
    }
});

// ═══════════════════════════════════════════════
//  USER MANAGEMENT
// ═══════════════════════════════════════════════

router.get('/users', async (req: AdminRequest, res: Response) => {
    try {
        const { page = '1', limit = '20', search, plan, status, sort = 'createdAt', order = 'desc' } = req.query;
        const pageNum = parseInt(page as string);
        const limitNum = parseInt(limit as string);

        let users: any[] = [];

        if (db) {
            try {
                let query = db.collection('users').orderBy(sort as string, order as 'asc' | 'desc');

                const snapshot = await query.limit(limitNum).offset((pageNum - 1) * limitNum).get();
                users = snapshot.docs.map(doc => ({ id: doc.id, ...doc.data() }));

                // Get total count
                const countSnapshot = await db.collection('users').count().get();
                const total = countSnapshot.data().count;

                return res.json({
                    users,
                    pagination: {
                        page: pageNum,
                        limit: limitNum,
                        total,
                        totalPages: Math.ceil(total / limitNum),
                    },
                });
            } catch (e) {
                console.error('Firebase users fetch error:', e);
            }
        }

        // Fallback: return empty
        res.json({
            users: [],
            pagination: { page: pageNum, limit: limitNum, total: 0, totalPages: 0 },
        });
    } catch (error) {
        console.error('Admin users error:', error);
        res.status(500).json({ error: 'Failed to fetch users' });
    }
});

router.get('/users/:id', async (req: AdminRequest, res: Response) => {
    try {
        const { id } = req.params;
        if (db) {
            const doc = await db.collection('users').doc(id).get();
            if (doc.exists) {
                // Also get user's email count
                const emailCount = await db.collection('messages')
                    .where('recipient', '==', doc.data()?.email)
                    .count().get();

                return res.json({
                    user: { id: doc.id, ...doc.data() },
                    emailsGenerated: emailCount.data().count,
                });
            }
        }
        res.status(404).json({ error: 'User not found' });
    } catch (error) {
        console.error('Admin user detail error:', error);
        res.status(500).json({ error: 'Failed to fetch user' });
    }
});

router.patch('/users/:id', async (req: AdminRequest, res: Response) => {
    try {
        const { id } = req.params;
        const { status, role, plan } = req.body;

        if (db) {
            const updateData: any = { updatedAt: new Date() };
            if (status) updateData.status = status;
            if (role) updateData.role = role;
            if (plan) updateData.plan = plan;

            await db.collection('users').doc(id).update(updateData);

            // Log the action
            await db.collection('admin_logs').add({
                action: 'user_updated',
                targetId: id,
                changes: updateData,
                adminEmail: req.admin?.email,
                timestamp: new Date(),
            });

            return res.json({ success: true, message: 'User updated' });
        }
        res.status(500).json({ error: 'Database not available' });
    } catch (error) {
        console.error('Admin user update error:', error);
        res.status(500).json({ error: 'Failed to update user' });
    }
});

router.delete('/users/:id', async (req: AdminRequest, res: Response) => {
    try {
        const { id } = req.params;
        if (db) {
            await db.collection('users').doc(id).delete();

            await db.collection('admin_logs').add({
                action: 'user_deleted',
                targetId: id,
                adminEmail: req.admin?.email,
                timestamp: new Date(),
            });

            return res.json({ success: true, message: 'User deleted' });
        }
        res.status(500).json({ error: 'Database not available' });
    } catch (error) {
        console.error('Admin user delete error:', error);
        res.status(500).json({ error: 'Failed to delete user' });
    }
});

router.post('/users/bulk-action', async (req: AdminRequest, res: Response) => {
    try {
        const { userIds, action } = req.body; // action: 'delete' | 'suspend' | 'activate'

        if (!Array.isArray(userIds) || userIds.length === 0) {
            return res.status(400).json({ error: 'userIds array is required' });
        }

        if (db) {
            const batch = db.batch();

            for (const uid of userIds) {
                const ref = db.collection('users').doc(uid);
                if (action === 'delete') {
                    batch.delete(ref);
                } else if (action === 'suspend') {
                    batch.update(ref, { status: 'suspended', updatedAt: new Date() });
                } else if (action === 'activate') {
                    batch.update(ref, { status: 'active', updatedAt: new Date() });
                }
            }

            await batch.commit();

            await db.collection('admin_logs').add({
                action: `bulk_${action}`,
                targetIds: userIds,
                count: userIds.length,
                adminEmail: req.admin?.email,
                timestamp: new Date(),
            });

            return res.json({ success: true, message: `${action} applied to ${userIds.length} users` });
        }
        res.status(500).json({ error: 'Database not available' });
    } catch (error) {
        console.error('Admin bulk action error:', error);
        res.status(500).json({ error: 'Failed to perform bulk action' });
    }
});

// ═══════════════════════════════════════════════
//  EMAIL MONITORING
// ═══════════════════════════════════════════════

router.get('/emails', async (req: AdminRequest, res: Response) => {
    try {
        const { page = '1', limit = '30', search, status: emailStatus, domain } = req.query;
        const pageNum = parseInt(page as string);
        const limitNum = parseInt(limit as string);

        let emails: any[] = [];
        let total = 0;

        if (db) {
            try {
                let query: any = db.collection('messages').orderBy('timestamp', 'desc');

                if (domain) {
                    query = query.where('recipient', '>=', `@${domain}`);
                }

                const snapshot = await query.limit(limitNum).offset((pageNum - 1) * limitNum).get();
                emails = snapshot.docs.map((doc: any) => ({
                    id: doc.id,
                    ...doc.data(),
                    timestamp: doc.data().timestamp?.toDate?.() || null,
                }));

                const countSnapshot = await db.collection('messages').count().get();
                total = countSnapshot.data().count;
            } catch (e) {
                console.error('Firebase emails fetch error:', e);
            }
        }

        // Also include in-memory inbox emails
        if (emails.length === 0) {
            inMemoryInbox.forEach((msgs, recipient) => {
                msgs.forEach(msg => {
                    emails.push({ ...msg, recipient, status: 'delivered' });
                });
            });
            total = emails.length;
            emails = emails.slice((pageNum - 1) * limitNum, pageNum * limitNum);
        }

        // Search filter
        if (search) {
            const searchStr = (search as string).toLowerCase();
            emails = emails.filter((e: any) =>
                e.recipient?.toLowerCase().includes(searchStr) ||
                e.sender?.toLowerCase().includes(searchStr) ||
                e.subject?.toLowerCase().includes(searchStr)
            );
        }

        res.json({
            emails,
            pagination: { page: pageNum, limit: limitNum, total, totalPages: Math.ceil(total / limitNum) },
        });
    } catch (error) {
        console.error('Admin emails error:', error);
        res.status(500).json({ error: 'Failed to fetch emails' });
    }
});

router.get('/emails/:id', async (req: AdminRequest, res: Response) => {
    try {
        const { id } = req.params;
        if (db) {
            const doc = await db.collection('messages').doc(id).get();
            if (doc.exists) {
                return res.json({ email: { id: doc.id, ...doc.data() } });
            }
        }
        res.status(404).json({ error: 'Email not found' });
    } catch (error) {
        res.status(500).json({ error: 'Failed to fetch email' });
    }
});

router.delete('/emails/:id', async (req: AdminRequest, res: Response) => {
    try {
        const { id } = req.params;
        if (db) {
            await db.collection('messages').doc(id).delete();
            return res.json({ success: true });
        }
        res.status(500).json({ error: 'Database not available' });
    } catch (error) {
        res.status(500).json({ error: 'Failed to delete email' });
    }
});

// Email traffic stats (hourly breakdown)
router.get('/emails/stats/traffic', async (req: AdminRequest, res: Response) => {
    try {
        const hours: any[] = [];
        const now = new Date();

        for (let i = 23; i >= 0; i--) {
            const hourStart = new Date(now);
            hourStart.setHours(now.getHours() - i, 0, 0, 0);
            const hourEnd = new Date(hourStart);
            hourEnd.setHours(hourStart.getHours() + 1);

            let delivered = 0, spam = 0, blocked = 0;

            if (db) {
                try {
                    const snapshot = await db.collection('messages')
                        .where('timestamp', '>=', hourStart)
                        .where('timestamp', '<', hourEnd)
                        .count().get();
                    delivered = snapshot.data().count;
                } catch (e) { }
            }

            hours.push({
                hour: `${hourStart.getHours().toString().padStart(2, '0')}:00`,
                delivered,
                spam,
                blocked,
            });
        }

        res.json({ traffic: hours });
    } catch (error) {
        res.status(500).json({ error: 'Failed to fetch email traffic' });
    }
});

// ═══════════════════════════════════════════════
//  DOMAIN MANAGEMENT
// ═══════════════════════════════════════════════

const DEFAULT_DOMAINS = [
    { name: 'appschai.site', status: 'active', type: 'free', mx: true, spf: true, dkim: true, ssl: true },
    { name: 'appschai.store', status: 'active', type: 'free', mx: true, spf: true, dkim: true, ssl: true },
    { name: 'appschai.space', status: 'active', type: 'free', mx: true, spf: true, dkim: true, ssl: true },
    { name: 'mailchai.com', status: 'active', type: 'free', mx: true, spf: true, dkim: false, ssl: true },
    { name: 'tempbox.site', status: 'active', type: 'premium', mx: true, spf: true, dkim: true, ssl: true },
    { name: 'ghostmail.io', status: 'active', type: 'premium', mx: true, spf: true, dkim: true, ssl: true },
    { name: 'anonmail.net', status: 'inactive', type: 'premium', mx: true, spf: false, dkim: false, ssl: true },
    { name: 'privybox.me', status: 'pending', type: 'premium', mx: false, spf: false, dkim: false, ssl: false },
];

router.get('/domains', async (req: AdminRequest, res: Response) => {
    try {
        let domains = [...DEFAULT_DOMAINS];

        // Enrich with email counts from database
        if (db) {
            for (const domain of domains) {
                try {
                    // Count total emails for this domain
                    // Firestore doesn't support LIKE queries, so we approximate
                    const snapshot = await db.collection('messages')
                        .where('recipient', '>=', `@${domain.name}`)
                        .where('recipient', '<=', `@${domain.name}\uf8ff`)
                        .count().get();

                    (domain as any).totalEmails = snapshot.data().count;
                } catch (e) {
                    (domain as any).totalEmails = 0;
                }
            }
        }

        res.json({ domains });
    } catch (error) {
        res.status(500).json({ error: 'Failed to fetch domains' });
    }
});

router.post('/domains', async (req: AdminRequest, res: Response) => {
    try {
        const { name, type = 'free' } = req.body;

        if (!name) {
            return res.status(400).json({ error: 'Domain name is required' });
        }

        if (db) {
            await db.collection('domains').doc(name).set({
                name,
                type,
                status: 'pending',
                mx: false, spf: false, dkim: false, ssl: false,
                createdAt: new Date(),
                createdBy: req.admin?.email,
            });

            await db.collection('admin_logs').add({
                action: 'domain_added',
                domain: name,
                adminEmail: req.admin?.email,
                timestamp: new Date(),
            });

            return res.json({ success: true, message: `Domain ${name} added` });
        }

        // In-memory fallback
        DEFAULT_DOMAINS.push({
            name, status: 'pending', type: type as string,
            mx: false, spf: false, dkim: false, ssl: false,
        });
        res.json({ success: true, message: `Domain ${name} added (in-memory)` });
    } catch (error) {
        res.status(500).json({ error: 'Failed to add domain' });
    }
});

router.delete('/domains/:name', async (req: AdminRequest, res: Response) => {
    try {
        const { name } = req.params;
        if (db) {
            await db.collection('domains').doc(name).delete();

            await db.collection('admin_logs').add({
                action: 'domain_removed',
                domain: name,
                adminEmail: req.admin?.email,
                timestamp: new Date(),
            });

            return res.json({ success: true });
        }
        res.status(500).json({ error: 'Database not available' });
    } catch (error) {
        res.status(500).json({ error: 'Failed to remove domain' });
    }
});

// ═══════════════════════════════════════════════
//  ANALYTICS
// ═══════════════════════════════════════════════

router.get('/analytics', async (req: AdminRequest, res: Response) => {
    try {
        const { range = '30d' } = req.query;
        let days = 30;
        if (range === '7d') days = 7;
        else if (range === '90d') days = 90;
        else if (range === '1y') days = 365;

        let totalEmails = 0, totalUsers = 0;

        if (db) {
            try {
                const emailCount = await db.collection('messages').count().get();
                totalEmails = emailCount.data().count;
            } catch (e) { }

            try {
                const userCount = await db.collection('users').count().get();
                totalUsers = userCount.data().count;
            } catch (e) { }
        }

        // Generate daily data points
        const dailyData: any[] = [];
        for (let i = days - 1; i >= 0; i--) {
            const date = new Date();
            date.setDate(date.getDate() - i);
            dailyData.push({
                date: date.toISOString().split('T')[0],
                emails: Math.floor(Math.random() * 500) + 100, // Replace with real query
                users: Math.floor(Math.random() * 20) + 5,
            });
        }

        res.json({
            totalEmails,
            totalUsers,
            dailyData,
            topCountries: [
                { country: 'United States', users: Math.floor(totalUsers * 0.25) },
                { country: 'India', users: Math.floor(totalUsers * 0.18) },
                { country: 'Brazil', users: Math.floor(totalUsers * 0.12) },
                { country: 'Germany', users: Math.floor(totalUsers * 0.08) },
                { country: 'Japan', users: Math.floor(totalUsers * 0.06) },
            ],
            deviceSplit: { desktop: 58, mobile: 35, tablet: 7 },
            trafficSources: [
                { source: 'Direct', visits: 45 },
                { source: 'Google', visits: 30 },
                { source: 'Social', visits: 15 },
                { source: 'Referral', visits: 10 },
            ],
        });
    } catch (error) {
        res.status(500).json({ error: 'Failed to fetch analytics' });
    }
});

// ═══════════════════════════════════════════════
//  ABUSE & SPAM
// ═══════════════════════════════════════════════

router.get('/abuse/blocked-ips', async (req: AdminRequest, res: Response) => {
    try {
        let blockedIPs: any[] = [];

        if (db) {
            const snapshot = await db.collection('blocked_ips').orderBy('blockedAt', 'desc').get();
            blockedIPs = snapshot.docs.map(doc => ({ id: doc.id, ...doc.data() }));
        }

        // Also check Redis for rate-limited IPs
        if (redisClient.isOpen) {
            try {
                const keys = await redisClient.keys('ratelimit:blocked:*');
                for (const key of keys) {
                    const ip = key.replace('ratelimit:blocked:', '');
                    const data = await redisClient.get(key);
                    if (data) {
                        blockedIPs.push({
                            ip,
                            reason: 'Rate limit exceeded (auto-blocked)',
                            severity: 'medium',
                            source: 'redis',
                            ...JSON.parse(data),
                        });
                    }
                }
            } catch (e) { }
        }

        res.json({ blockedIPs });
    } catch (error) {
        res.status(500).json({ error: 'Failed to fetch blocked IPs' });
    }
});

router.post('/abuse/block-ip', async (req: AdminRequest, res: Response) => {
    try {
        const { ip, reason, severity = 'medium' } = req.body;

        if (!ip) {
            return res.status(400).json({ error: 'IP address is required' });
        }

        const blockData = {
            ip,
            reason: reason || 'Manually blocked by admin',
            severity,
            blockedAt: new Date(),
            blockedBy: req.admin?.email,
        };

        if (db) {
            await db.collection('blocked_ips').doc(ip.replace(/\./g, '_')).set(blockData);

            await db.collection('admin_logs').add({
                action: 'ip_blocked',
                ip,
                reason,
                adminEmail: req.admin?.email,
                timestamp: new Date(),
            });
        }

        // Also block in Redis for real-time enforcement
        if (redisClient.isOpen) {
            await redisClient.set(`blocked:${ip}`, JSON.stringify(blockData), { EX: 86400 * 365 }); // 1 year
        }

        res.json({ success: true, message: `IP ${ip} blocked` });
    } catch (error) {
        res.status(500).json({ error: 'Failed to block IP' });
    }
});

router.delete('/abuse/unblock-ip/:ip', async (req: AdminRequest, res: Response) => {
    try {
        const { ip } = req.params;

        if (db) {
            await db.collection('blocked_ips').doc(ip.replace(/\./g, '_')).delete();
        }

        if (redisClient.isOpen) {
            await redisClient.del(`blocked:${ip}`);
        }

        res.json({ success: true, message: `IP ${ip} unblocked` });
    } catch (error) {
        res.status(500).json({ error: 'Failed to unblock IP' });
    }
});

router.get('/abuse/blocked-domains', async (req: AdminRequest, res: Response) => {
    try {
        let blockedDomains: any[] = [];

        if (db) {
            const snapshot = await db.collection('blocked_domains').orderBy('blockedAt', 'desc').get();
            blockedDomains = snapshot.docs.map(doc => ({ id: doc.id, ...doc.data() }));
        }

        res.json({ blockedDomains });
    } catch (error) {
        res.status(500).json({ error: 'Failed to fetch blocked domains' });
    }
});

router.post('/abuse/block-domain', async (req: AdminRequest, res: Response) => {
    try {
        const { domain, reason } = req.body;

        if (!domain) {
            return res.status(400).json({ error: 'Domain is required' });
        }

        if (db) {
            await db.collection('blocked_domains').doc(domain).set({
                domain,
                reason: reason || 'Manually blocked',
                blockedAt: new Date(),
                blockedBy: req.admin?.email,
                emailsBlocked: 0,
            });
        }

        res.json({ success: true, message: `Domain ${domain} blocked` });
    } catch (error) {
        res.status(500).json({ error: 'Failed to block domain' });
    }
});

// ═══════════════════════════════════════════════
//  SYSTEM LOGS
// ═══════════════════════════════════════════════

router.get('/logs', async (req: AdminRequest, res: Response) => {
    try {
        const { page = '1', limit = '50', level, source } = req.query;
        const pageNum = parseInt(page as string);
        const limitNum = parseInt(limit as string);

        let logs: any[] = [];
        let total = 0;

        if (db) {
            let query: any = db.collection('admin_logs').orderBy('timestamp', 'desc');

            if (level && level !== 'All') {
                query = query.where('level', '==', (level as string).toLowerCase());
            }

            const snapshot = await query.limit(limitNum).offset((pageNum - 1) * limitNum).get();
            logs = snapshot.docs.map((doc: any) => ({
                id: doc.id,
                ...doc.data(),
                timestamp: doc.data().timestamp?.toDate?.()?.toISOString() || null,
            }));

            const countSnapshot = await db.collection('admin_logs').count().get();
            total = countSnapshot.data().count;
        }

        res.json({
            logs,
            pagination: { page: pageNum, limit: limitNum, total, totalPages: Math.ceil(total / limitNum) },
            queueStats: {
                emailDelivery: { pending: 0, processing: 0, completed: 0, failed: 0 },
                spamAnalysis: { pending: 0, processing: 0, completed: 0, failed: 0 },
            },
        });
    } catch (error) {
        res.status(500).json({ error: 'Failed to fetch logs' });
    }
});

// ═══════════════════════════════════════════════
//  PAYMENTS
// ═══════════════════════════════════════════════

router.get('/payments', async (req: AdminRequest, res: Response) => {
    try {
        const { page = '1', limit = '20', search } = req.query;
        const pageNum = parseInt(page as string);
        const limitNum = parseInt(limit as string);

        let transactions: any[] = [];
        let total = 0;
        let revenueMTD = 0;

        if (db) {
            try {
                const snapshot = await db.collection('payments')
                    .orderBy('createdAt', 'desc')
                    .limit(limitNum)
                    .offset((pageNum - 1) * limitNum)
                    .get();

                transactions = snapshot.docs.map(doc => ({
                    id: doc.id,
                    ...doc.data(),
                    createdAt: doc.data().createdAt?.toDate?.()?.toISOString() || null,
                }));

                const countSnapshot = await db.collection('payments').count().get();
                total = countSnapshot.data().count;

                // Calculate MTD revenue
                const monthStart = new Date();
                monthStart.setDate(1);
                monthStart.setHours(0, 0, 0, 0);

                const mtdSnapshot = await db.collection('payments')
                    .where('createdAt', '>=', monthStart)
                    .where('status', '==', 'completed')
                    .get();

                revenueMTD = mtdSnapshot.docs.reduce((sum, doc) => sum + (doc.data().amount || 0), 0);
            } catch (e) {
                console.error('Firebase payments error:', e);
            }
        }

        res.json({
            transactions,
            pagination: { page: pageNum, limit: limitNum, total, totalPages: Math.ceil(total / limitNum) },
            stats: {
                revenueMTD,
                totalSubscribers: 0,
                mrr: 0,
                avgRevenuePerUser: 0,
            },
        });
    } catch (error) {
        res.status(500).json({ error: 'Failed to fetch payments' });
    }
});

// ═══════════════════════════════════════════════
//  SETTINGS
// ═══════════════════════════════════════════════

router.get('/settings', async (req: AdminRequest, res: Response) => {
    try {
        let settings: any = {};

        if (db) {
            const doc = await db.collection('system').doc('settings').get();
            if (doc.exists) {
                settings = doc.data();
            }
        }

        // Merge with defaults
        const defaults = {
            siteName: 'TempWorld',
            siteUrl: 'https://tempworld.org',
            adminEmail: 'admin@tempworld.org',
            maintenanceMode: false,
            emailRetention: 60,
            maxMailboxSize: 50,
            autoDeleteEnabled: true,
            maxEmailSize: 25,
            allowAttachments: true,
            maxAttachmentSize: 10,
            spamFilterEnabled: true,
            spamThreshold: 7,
            autoBlockSpam: true,
            rateLimitEnabled: true,
            rateLimitRequests: 100,
            rateLimitWindow: 15,
            sessionTimeout: 30,
            twoFactorRequired: false,
            csrfProtection: true,
            emailNotifications: true,
            slackNotifications: false,
            alertOnError: true,
            alertOnSpam: true,
            dailyDigest: true,
        };

        res.json({ settings: { ...defaults, ...settings } });
    } catch (error) {
        res.status(500).json({ error: 'Failed to fetch settings' });
    }
});

router.put('/settings', async (req: AdminRequest, res: Response) => {
    try {
        const newSettings = req.body;

        if (db) {
            await db.collection('system').doc('settings').set(newSettings, { merge: true });

            await db.collection('admin_logs').add({
                action: 'settings_updated',
                changes: Object.keys(newSettings),
                adminEmail: req.admin?.email,
                timestamp: new Date(),
            });

            return res.json({ success: true, message: 'Settings saved' });
        }

        res.status(500).json({ error: 'Database not available' });
    } catch (error) {
        res.status(500).json({ error: 'Failed to save settings' });
    }
});

// ═══════════════════════════════════════════════
//  ADMIN AUTH (login history, profile)
// ═══════════════════════════════════════════════

router.get('/profile', async (req: AdminRequest, res: Response) => {
    res.json({
        admin: {
            id: req.admin?.id,
            email: req.admin?.email,
            role: req.admin?.role,
        },
    });
});

router.get('/login-history', async (req: AdminRequest, res: Response) => {
    try {
        let history: any[] = [];

        if (db) {
            const snapshot = await db.collection('admin_logs')
                .where('action', '==', 'admin_login')
                .orderBy('timestamp', 'desc')
                .limit(20)
                .get();

            history = snapshot.docs.map(doc => ({
                id: doc.id,
                ...doc.data(),
                timestamp: doc.data().timestamp?.toDate?.()?.toISOString() || null,
            }));
        }

        res.json({ history });
    } catch (error) {
        res.status(500).json({ error: 'Failed to fetch login history' });
    }
});

export default router;
