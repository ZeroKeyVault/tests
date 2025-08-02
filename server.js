const WebSocket = require('ws');
const crypto = require('crypto');

// Server configuration
const PORT = process.env.PORT || 8080;

// In-memory data stores
// Maps a user ID to their WebSocket connection
const clients = new Map();
// Stores vault data: { vaultId, vaultName, members[], expiration, type, messages[], key, ... }
const vaults = new Map();
// Maps a vault hash to its vault ID
const vaultHashes = new Map();
// Stores messages that couldn't be relayed because a user was offline
const offlineMessages = new Map();

// --- Utility Functions for Cryptography and Data ---

// Generates a random hash for public vaults
function generateVaultHash() {
    return crypto.randomBytes(32).toString('hex');
}

// Derives a key from a hash and salt
async function deriveKeyFromHash(vaultHash, salt) {
    const keyMaterial = await crypto.subtle.importKey(
        "raw",
        Buffer.from(vaultHash),
        { name: "PBKDF2" },
        false,
        ["deriveKey"]
    );
    return crypto.subtle.deriveKey(
        {
            name: "PBKDF2",
            salt: salt,
            iterations: 100000,
            hash: "SHA-256",
        },
        keyMaterial,
        { name: "AES-GCM", length: 256 },
        true,
        ["encrypt", "decrypt"]
    );
}

// Derives a key from a shared secret and salt (for Kyber)
async function deriveVaultKeyFromSharedSecret(sharedSecret, salt) {
    const keyMaterial = await crypto.subtle.importKey(
        "raw",
        Buffer.from(sharedSecret),
        { name: "PBKDF2" },
        false,
        ["deriveKey"]
    );
    return crypto.subtle.deriveKey(
        {
            name: "PBKDF2",
            salt: salt,
            iterations: 100000,
            hash: "SHA-256",
        },
        keyMaterial,
        { name: "AES-GCM", length: 256 },
        true,
        ["encrypt", "decrypt"]
    );
}

// Encrypts data using a given key
async function encryptData(data, key) {
    const iv = crypto.webcrypto.getRandomValues(new Uint8Array(12));
    const encryptedData = await crypto.subtle.encrypt(
        { name: "AES-GCM", iv: iv },
        key,
        data
    );
    return { encryptedData, iv };
}

// Converts a duration string (e.g., '1h', '1mo') to milliseconds
function parseExpirationTime(duration) {
    const unit = duration.slice(-2);
    const value = parseInt(duration.slice(0, -2), 10);
    switch (unit) {
        case 'h': return value * 60 * 60 * 1000;
        case 'mo': return value * 30 * 24 * 60 * 60 * 1000; // approximation
        case 'yr': return value * 365 * 24 * 60 * 60 * 1000; // approximation
        default: return 0; // 'never' or invalid
    }
}

// Checks for and removes expired vaults
function cleanupExpiredVaults() {
    const now = Date.now();
    for (const [vaultId, vault] of vaults.entries()) {
        if (vault.expiration > 0 && now > vault.expiration) {
            console.log(`Vault ${vaultId} expired. Removing.`);
            
            // Notify all members that the vault is expired
            const message = JSON.stringify({
                type: 'vault_expired_notification',
                expiredVaultId: vaultId,
                expiredVaultName: vault.vaultName
            });
            vault.members.forEach(memberId => {
                const client = clients.get(memberId);
                if (client && client.readyState === WebSocket.OPEN) {
                    client.send(message);
                }
            });

            // Clean up data stores
            vaults.delete(vaultId);
            vaultHashes.delete(vault.vaultHash);
            offlineMessages.delete(vaultId);
        }
    }
}

// Set up a timer to check for expired vaults every hour
setInterval(cleanupExpiredVaults, 60 * 60 * 1000);

// --- WebSocket Server Setup ---
const wss = new WebSocket.Server({ port: PORT });

wss.on('connection', ws => {
    console.log('Client connected.');
    let currentUserId = null;

    // Handle incoming messages from clients
    ws.on('message', async message => {
        let data;
        try {
            data = JSON.parse(message);
        } catch (e) {
            console.error('Failed to parse message:', e);
            return;
        }

        console.log('Received:', data);

        switch (data.type) {
            case 'register':
                currentUserId = data.userId;
                clients.set(currentUserId, ws);
                console.log(`User ${currentUserId} registered.`);
                checkAndSendOfflineMessages(currentUserId);
                break;

            case 'create_vault':
                {
                    const { userId, vaultName, vaultType, expiration, kemPublicKeyB64, saltB64 } = data;
                    const vaultId = crypto.randomUUID();
                    const vaultHash = generateVaultHash();
                    const now = Date.now();
                    const expirationTime = expiration === 'never' ? 0 : now + parseExpirationTime(expiration);
                    
                    let aesKey;
                    let encryptedKey;
                    let iv;
                    
                    if (vaultType === 'private') {
                        // For private vaults, the server does not handle any cryptography.
                        console.log(`Private vault created. Server will act as a simple message relay.`);
                    } else { // public vault
                        aesKey = await crypto.subtle.generateKey(
                            { name: "AES-GCM", length: 256 },
                            true,
                            ["encrypt", "decrypt"]
                        );
                        
                        const exportedKey = await crypto.subtle.exportKey('raw', aesKey);
                        const salt = crypto.webcrypto.getRandomValues(new Uint8Array(16));
                        const derivedKey = await deriveKeyFromHash(vaultHash, salt);
                        const encryptedResult = await encryptData(exportedKey, derivedKey);
                        encryptedKey = Buffer.from(encryptedResult.encryptedData).toString('base64');
                        iv = Buffer.from(encryptedResult.iv).toString('base64');
                    }
                    
                    vaults.set(vaultId, {
                        vaultId: vaultId,
                        vaultName: vaultName,
                        vaultHash: vaultHash,
                        members: [userId],
                        expiration: expirationTime,
                        type: vaultType,
                        aesKey: aesKey,
                        messages: [],
                        salt: saltB64 ? Buffer.from(saltB64, 'base64') : null,
                    });
                    vaultHashes.set(vaultHash, vaultId);

                    // Send the vault info back to the creator
                    const response = {
                        type: 'vault_created',
                        vaultId: vaultId,
                        vaultName: vaultName,
                        vaultHash: vaultHash,
                        vaultType: vaultType,
                        expiration: expirationTime,
                        saltB64: saltB64
                    };
                    
                    if (vaultType === 'public') {
                        response.encryptedKeyB64 = encryptedKey;
                        response.ivB64 = iv;
                        response.saltB64 = Buffer.from(vaults.get(vaultId).salt).toString('base64');
                    }
                    
                    ws.send(JSON.stringify(response));
                    console.log(`Vault ${vaultId} created by ${userId}. Type: ${vaultType}`);
                }
                break;

            case 'join_vault':
                {
                    const { userId, vaultHash, kemPublicKeyB64 } = data;
                    const vaultId = vaultHashes.get(vaultHash);
                    if (!vaultId) {
                        ws.send(JSON.stringify({ type: 'error', message: 'Vault not found.' }));
                        return;
                    }

                    const vault = vaults.get(vaultId);
                    if (vault.members.includes(userId)) {
                        ws.send(JSON.stringify({ type: 'error', message: 'You are already a member of this vault.' }));
                        return;
                    }

                    vault.members.push(userId);

                    let encryptedKey;
                    let iv;
                    
                    // Send the vault info back to the joining user
                    const response = {
                        type: 'vault_joined',
                        joinedVaultId: vaultId,
                        joinedVaultName: vault.vaultName,
                        joinedVaultType: vault.type,
                        joinedExpiration: vault.expiration,
                        vaultHash: vaultHash,
                    };
                    
                    if (vault.type === 'public') {
                        const exportedKey = await crypto.subtle.exportKey('raw', vault.aesKey);
                        const salt = Buffer.from(vault.salt, 'base64');
                        const derivedKey = await deriveKeyFromHash(vaultHash, salt);
                        const encryptedResult = await encryptData(exportedKey, derivedKey);
                        encryptedKey = Buffer.from(encryptedResult.encryptedData).toString('base64');
                        iv = Buffer.from(encryptedResult.iv).toString('base64');
                        
                        response.encryptedKeyB64 = encryptedKey;
                        response.ivB64 = iv;
                        response.saltB64 = Buffer.from(vaults.get(vaultId).salt).toString('base64');
                    }
                    
                    ws.send(JSON.stringify(response));
                    console.log(`User ${userId} joined vault ${vaultId}.`);
                }
                break;
                
            case 'send_message':
                {
                    const { vaultId, senderId, encryptedMessage, iv, timestamp, isFile, fileName, fileMimeType } = data;
                    const vault = vaults.get(vaultId);
                    if (vault) {
                        const messageObj = { vaultId, senderId, encryptedMessage, iv, timestamp, isFile, fileName, fileMimeType };
                        broadcastToVault(vaultId, messageObj, senderId);
                        vault.messages.push(messageObj);
                        console.log(`Message relayed in vault ${vaultId}.`);
                    }
                }
                break;
        }
    });

    // Handle client disconnect
    ws.on('close', () => {
        if (currentUserId) {
            clients.delete(currentUserId);
            console.log(`User ${currentUserId} disconnected.`);
        }
    });
    
    // Handle errors
    ws.on('error', error => {
        console.error('WebSocket error:', error);
    });
});

// Broadcast a message to all members of a vault, except the sender
function broadcastToVault(vaultId, message, senderId) {
    const vault = vaults.get(vaultId);
    if (!vault) return;

    const jsonMessage = JSON.stringify({ type: 'new_message', ...message });

    for (const memberId of vault.members) {
        if (memberId !== senderId) {
            const client = clients.get(memberId);
            if (client && client.readyState === WebSocket.OPEN) {
                client.send(jsonMessage);
            } else {
                // Store message for offline user
                if (!offlineMessages.has(memberId)) {
                    offlineMessages.set(memberId, []);
                }
                offlineMessages.get(memberId).push({ vaultId, message });
                console.log(`Stored message for offline user: ${memberId}`);
            }
        }
    }
}

// Check for and send offline messages to a reconnecting user
function checkAndSendOfflineMessages(userId) {
    if (offlineMessages.has(userId)) {
        const messagesToSend = offlineMessages.get(userId);
        if (messagesToSend.length > 0) {
            const client = clients.get(userId);
            if (client && client.readyState === WebSocket.OPEN) {
                // Send all pending messages
                const messageData = messagesToSend.map(m => m.message);
                const offlineMessage = {
                    type: 'offline_messages',
                    messages: messageData
                };
                client.send(JSON.stringify(offlineMessage));
                offlineMessages.delete(userId);
                console.log(`Sent ${messageData.length} offline messages to ${userId}.`);
            }
        }
    }
}

console.log(`WebSocket server started on port ${PORT}`);
