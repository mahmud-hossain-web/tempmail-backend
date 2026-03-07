import { SMTPServer } from 'smtp-server';
import { simpleParser } from 'mailparser';
let ioInstance: any;
import redisClient from './redis';
import { db } from './utils/firebaseAdmin';
import * as admin from 'firebase-admin';

export const inMemoryInbox = new Map<string, any[]>();

const smtpOptions = {
    secure: false,
    authOptional: true,
    onData(stream: any, session: any, callback: () => void) {
        simpleParser(stream, async (err, parsed) => {
            if (err) {
                console.error("Parse Error:", err);
            } else {
                try {
                    const recipients = session.envelope.rcptTo.map((r: any) => r.address);

                    for (let recipient of recipients) {
                        recipient = (recipient || '').toLowerCase();
                        console.log(`New mail received for target address: ${recipient}`);

                        const messageData = {
                            id: Date.now().toString(),
                            sender: parsed.from?.text || 'Unknown',
                            subject: parsed.subject || 'No Subject',
                            time: new Date().toLocaleTimeString(),
                            body: parsed.text || parsed.html || '',
                        };

                        // emit realtime
                        if (ioInstance) {
                            ioInstance.to(recipient).emit('new_email', messageData);
                        }

                        // save in memory
                        const currentMessages = inMemoryInbox.get(recipient) || [];
                        inMemoryInbox.set(recipient, [messageData, ...currentMessages]);

                        // save in firebase
                        if (db) {
                            try {
                                const docRef = db.collection('messages').doc(messageData.id);
                                await docRef.set({
                                    ...messageData,
                                    recipient: recipient,
                                    timestamp: admin.firestore.FieldValue.serverTimestamp()
                                });
                            } catch (error) {
                                console.error("Firebase DB error saving email", error);
                            }
                        }

                        // cache to redis (for reconnects)
                        if (redisClient.isOpen) {
                            try {
                                await redisClient.lPush(`inbox:${recipient}`, JSON.stringify(messageData));
                            } catch (err) {
                                console.error("Redis Error saving email", err);
                            }
                        }
                    }
                } catch (internalError) {
                    console.error("Internal processing error:", internalError);
                }
            }
            callback();
        });
    }
};

const server = new SMTPServer(smtpOptions);

export const startSMTPServer = (port = 25, ioObj?: any) => {
    if (ioObj) ioInstance = ioObj;
    server.listen(port, () => {
        console.log(`SMTP server listening on port ${port}`);
    });
};
