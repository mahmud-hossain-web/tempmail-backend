import * as admin from 'firebase-admin';
import dotenv from 'dotenv';
dotenv.config();

// Usually, you should place your private key in an env variable or json file
// For example: FIREBASE_SERVICE_ACCOUNT_KEY='{ "type": "service_account", ... }'
// As a placeholder, we only initialize if the project details are present

if (process.env.FIREBASE_PROJECT_ID) {
    try {
        admin.initializeApp({
            credential: admin.credential.cert({
                projectId: process.env.FIREBASE_PROJECT_ID,
                clientEmail: process.env.FIREBASE_CLIENT_EMAIL,
                // replace escaped newlines with actual newlines
                privateKey: process.env.FIREBASE_PRIVATE_KEY?.replace(/\\n/g, '\n'),
            }),
        });
        console.log('Firebase Admin initialized successfully.');
    } catch (error) {
        console.error('Firebase Admin initialization error:', error);
    }
} else {
    console.warn('Firebase Admin NOT initialized. Please set FIREBASE_PROJECT_ID, FIREBASE_CLIENT_EMAIL, and FIREBASE_PRIVATE_KEY in .env');
}

export const auth = admin.auth ? admin.auth() : null;
export const db = admin.firestore ? admin.firestore() : null;
