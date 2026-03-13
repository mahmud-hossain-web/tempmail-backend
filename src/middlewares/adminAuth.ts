import { Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';

const JWT_SECRET = process.env.JWT_SECRET || 'super-secret-tempmail-key-123';

// Admin emails whitelist (same as frontend)
const ADMIN_EMAILS = ['mahmudhasan01726@gmail.com'];

export interface AdminRequest extends Request {
    admin?: { id: string; email: string; role: string };
}

/**
 * Middleware: Verify JWT and check admin role
 */
export const requireAdmin = (req: AdminRequest, res: Response, next: NextFunction) => {
    try {
        const authHeader = req.headers.authorization;
        if (!authHeader || !authHeader.startsWith('Bearer ')) {
            return res.status(401).json({ error: 'Unauthorized: No token provided' });
        }

        const token = authHeader.split(' ')[1];
        const decoded = jwt.verify(token, JWT_SECRET) as { id: string; email: string; role: string };

        // Check if user email is in admin whitelist or has admin/superadmin role
        if (!ADMIN_EMAILS.includes(decoded.email) && !['admin', 'superadmin'].includes(decoded.role)) {
            return res.status(403).json({ error: 'Forbidden: Admin access required' });
        }

        req.admin = decoded;
        next();
    } catch (error) {
        return res.status(401).json({ error: 'Unauthorized: Invalid or expired token' });
    }
};

/**
 * Middleware: Require superadmin role for destructive operations
 */
export const requireSuperAdmin = (req: AdminRequest, res: Response, next: NextFunction) => {
    try {
        const authHeader = req.headers.authorization;
        if (!authHeader || !authHeader.startsWith('Bearer ')) {
            return res.status(401).json({ error: 'Unauthorized: No token provided' });
        }

        const token = authHeader.split(' ')[1];
        const decoded = jwt.verify(token, JWT_SECRET) as { id: string; email: string; role: string };

        if (decoded.role !== 'superadmin' && decoded.email !== 'mahmudhasan01726@gmail.com') {
            return res.status(403).json({ error: 'Forbidden: Super Admin access required' });
        }

        req.admin = decoded;
        next();
    } catch (error) {
        return res.status(401).json({ error: 'Unauthorized: Invalid or expired token' });
    }
};

/**
 * Dev bypass: Skip auth in development when ADMIN_DEV_BYPASS=true
 */
export const adminAuthOrDev = (req: AdminRequest, res: Response, next: NextFunction) => {
    if (process.env.ADMIN_DEV_BYPASS === 'true') {
        req.admin = { id: 'dev', email: 'dev@tempworld.org', role: 'superadmin' };
        return next();
    }
    return requireAdmin(req, res, next);
};
