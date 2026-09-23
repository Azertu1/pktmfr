const express = require('express');
const si = require('systeminformation');
const { Pool } = require('pg');
const session = require('express-session');
const { Provider } = require('oidc-provider');
const {
    generateRegistrationOptions, verifyRegistrationResponse,
    generateAuthenticationOptions, verifyAuthenticationResponse
} = require('@simplewebauthn/server');

const app = express();
app.use(express.json());

// --- 1. CONFIGURATION BASE DE DONNÉES POSTGRESQL ---
const pool = new Pool({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
});

// Création automatique des tables au démarrage
pool.query(`
    CREATE TABLE IF NOT EXISTS users (id VARCHAR(50) PRIMARY KEY, username VARCHAR(255) UNIQUE);
    CREATE TABLE IF NOT EXISTS passkeys (
        credential_id TEXT PRIMARY KEY,
        user_id VARCHAR(50) REFERENCES users(id),
        public_key BYTEA,
        counter BIGINT
    );
    -- Utilisateur de test (toi)
    INSERT INTO users (id, username) VALUES ('user_isidore', 'isidore@pktm.fr') ON CONFLICT DO NOTHING;
`).catch(console.error);

// --- 2. CONFIGURATION SSO (OIDC) ---

// PARAMÈTRES FIXES (Pour contourner les problèmes de reverse proxy Nginx)
const rpName = 'pktm.fr SSO';
const rpID = 'pktm.fr';
const expectedOrigin = 'https://pktm.fr';

const oidcConfig = {
    clients: [{
        client_id: 'futur-projet-1',
        client_secret: 'secret-a-changer-en-prod',
        grant_types: ['authorization_code'],
        redirect_uris: ['https://pktm.fr/callback'], // Adapté pour ton domaine
    }],
    interactions: {
        url(ctx, interaction) {
            return `/login.html?uid=${interaction.uid}`;
        },
    },
    features: { devInteractions: { enabled: false } },
    cookies: { keys: ['une-cle-secrete-pour-les-cookies'] }
};
const oidc = new Provider('https://pktm.fr/oidc', oidcConfig);

app.use(session({ secret: 'pktm-secret', resave: false, saveUninitialized: true }));


// --- 3. ROUTES API PASSKEY ---

app.get('/api/register/options', async (req, res) => {
    try {
        const user = { id: 'user_isidore', username: 'isidore@pktm.fr' };

        const options = await generateRegistrationOptions({
            rpName,
            rpID, // Utilisation de la constante 'pktm.fr'
            userID: new Uint8Array(Buffer.from(user.id)),
            userName: user.username,
            authenticatorSelection: { userVerification: 'preferred' }
        });

        req.session.challenge = options.challenge;
        res.json(options);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.post('/api/register/verify', async (req, res) => {
    try {
        if (!req.session || !req.session.challenge) {
            return res.status(400).json({ error: 'Session expirée, rechargez la page.' });
        }

        const verification = await verifyRegistrationResponse({
            response: req.body,
            expectedChallenge: req.session.challenge,
            expectedOrigin, // Utilisation de 'https://pktm.fr'
            expectedRPID: rpID
        });

        if (verification.verified) {
            const { credentialID, credentialPublicKey, counter } = verification.registrationInfo;
            const credentialIdBase64url = Buffer.from(credentialID).toString('base64url');

            // CORRECTION MAJEURE : Conversion du Uint8Array en Buffer pour Postgres
            const publicKeyBuffer = Buffer.from(credentialPublicKey);

            await pool.query(
                'INSERT INTO passkeys (credential_id, user_id, public_key, counter) VALUES ($1, $2, $3, $4)',
                [credentialIdBase64url, 'user_isidore', publicKeyBuffer, counter]
            );
            return res.json({ verified: true });
        }
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
});

app.get('/api/login/options', async (req, res) => {
    try {
        const { rows } = await pool.query("SELECT credential_id FROM passkeys WHERE user_id = 'user_isidore'");

        const options = await generateAuthenticationOptions({
            rpID,
            userVerification: 'preferred',
            allowCredentials: rows.map(row => ({
                id: row.credential_id,
                type: 'public-key'
            }))
        });

        req.session.challenge = options.challenge;
        res.json(options);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.post('/api/login/verify', async (req, res) => {
    try {
        if (!req.session || !req.session.challenge) {
            return res.status(400).json({ error: 'Session expirée, rechargez la page.' });
        }

        const body = req.body;
        const { rows } = await pool.query('SELECT * FROM passkeys WHERE credential_id = $1', [body.id]);

        if (rows.length === 0) return res.status(400).json({ error: 'Passkey inconnu sur le serveur' });

        const passkey = rows[0];

        const verification = await verifyAuthenticationResponse({
            response: body,
            expectedChallenge: req.session.challenge,
            expectedOrigin, // Constante https
            expectedRPID: rpID, // Constante pktm.fr
            authenticator: {
                credentialID: new Uint8Array(Buffer.from(passkey.credential_id, 'base64url')),
                credentialPublicKey: new Uint8Array(passkey.public_key), // public_key est bien récupéré comme Buffer de Postgres
                counter: parseInt(passkey.counter, 10)
            }
        });

        if (verification.verified) {
            await pool.query('UPDATE passkeys SET counter = $1 WHERE credential_id = $2', [verification.authenticationInfo.newCounter, passkey.credential_id]);

            const uid = req.query.uid;
            if (uid) {
                const result = { login: { accountId: passkey.user_id } };
                const redirectTo = await oidc.interactionResult(req, res, uid, result);
                return res.json({ verified: true, redirectTo });
            }
            res.json({ verified: true, username: passkey.user_id });
        }
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
});

// --- 4. ROUTES EXISTANTES ET MIDDLEWARES ---
app.get('/api/metrics', async (req, res) => {
    try {
        const cpu = await si.currentLoad();
        const mem = await si.mem();
        const fs = await si.fsSize();
        const net = await si.networkStats();

        res.json({
            cpu: cpu.currentLoad,
            memory: (mem.active / mem.total) * 100,
            disk: fs[0] ? fs[0].use : 0,
            network: net[0] ? (net[0].tx_sec + net[0].rx_sec) / 1024 / 1024 : 0
        });
    } catch (error) {
        res.status(500).json({ error: 'Erreur de lecture' });
    }
});

app.use('/oidc', oidc.callback());
app.listen(3000, () => console.log('API et SSO prêts sur le port 3000'));