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
const oidcConfig = {
    clients: [{
        client_id: 'futur-projet-1',
        client_secret: 'secret-a-changer-en-prod',
        grant_types: ['authorization_code'],
        redirect_uris: ['http://localhost:8080/callback'], // URL où le SSO renverra l'utilisateur
    }],
    interactions: {
        url(ctx, interaction) {
            // Demande à Nginx d'afficher ton frontend de login avec l'ID de session OIDC
            return `/login.html?uid=${interaction.uid}`;
        },
    },
    features: { devInteractions: { enabled: false } },
    cookies: { keys: ['une-cle-secrete-pour-les-cookies'] }
};
const oidc = new Provider('http://localhost:8080/oidc', oidcConfig);

// Les sessions Express servent à retenir le "challenge" WebAuthn
app.use(session({ secret: 'pktm-secret', resave: false, saveUninitialized: true }));

const rpName = 'pktm.fr SSO';
const rpID = 'localhost'; // À remplacer par pktm.fr en production
const origin = `http://localhost:8080`; // À remplacer par https://pktm.fr en production

// --- 3. ROUTES API PASSKEY ---

// Création d'un nouveau Passkey
// --- 3. ROUTES API PASSKEY ---

// --- 3. ROUTES API PASSKEY ---

// Création d'un nouveau Passkey
app.get('/api/register/options', async (req, res) => {
    try {
        const user = { id: 'user_isidore', username: 'isidore@pktm.fr' };

        const options = await generateRegistrationOptions({
            rpName: 'pktm.fr SSO',
            // DYNAMIQUE : S'adapte à localhost, 127.0.0.1 ou pktm.fr
            rpID: req.hostname,
            // CORRECTION : La v9 exige un Uint8Array pour l'ID utilisateur
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
            return res.status(400).json({ error: 'Session expirée' });
        }

        // DYNAMIQUE : Récupère l'origine exacte (ex: http://127.0.0.1:8080)
        const origin = `${req.protocol}://${req.get('host')}`;

        const verification = await verifyRegistrationResponse({
            response: req.body,
            expectedChallenge: req.session.challenge,
            expectedOrigin: origin,
            expectedRPID: req.hostname
        });

        if (verification.verified) {
            const { credentialID, credentialPublicKey, counter } = verification.registrationInfo;

            // CORRECTION : On convertit explicitement en chaîne Base64URL
            const credentialIdBase64url = Buffer.from(credentialID).toString('base64url');

            await pool.query(
                'INSERT INTO passkeys (credential_id, user_id, public_key, counter) VALUES ($1, $2, $3, $4)',
                [credentialIdBase64url, 'user_isidore', credentialPublicKey, counter]
            );
            return res.json({ verified: true });
        }
    } catch (error) {
        res.status(400).json({ error: error.message });
    }
});

// Authentification avec un Passkey
app.get('/api/login/options', async (req, res) => {
    try {
        const { rows } = await pool.query("SELECT credential_id FROM passkeys WHERE user_id = 'user_isidore'");

        const options = await generateAuthenticationOptions({
            rpID: req.hostname,
            userVerification: 'preferred',
            allowCredentials: rows.map(row => ({
                // CORRECTION : L'ID est maintenant envoyé sous forme de chaîne de caractères pure
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
            return res.status(400).json({ error: 'Session expirée, veuillez recharger la page.' });
        }

        const body = req.body;

        // CORRECTION 1 : Gérer le proxy Nginx en récupérant l'origine réelle du navigateur
        const expectedOrigin = req.get('origin') || `${req.headers['x-forwarded-proto'] || req.protocol}://${req.get('host')}`;

        const { rows } = await pool.query('SELECT * FROM passkeys WHERE credential_id = $1', [body.id]);
        if (rows.length === 0) return res.status(400).json({ error: 'Passkey inconnu' });

        const passkey = rows[0];

        const verification = await verifyAuthenticationResponse({
            response: body,
            expectedChallenge: req.session.challenge,
            expectedOrigin: expectedOrigin, // <-- Utilisation de l'origine corrigée
            expectedRPID: req.hostname,
            authenticator: {
                credentialID: new Uint8Array(Buffer.from(passkey.credential_id, 'base64url')),
                credentialPublicKey: new Uint8Array(passkey.public_key),
                // CORRECTION 2 : Convertir le String renvoyé par PostgreSQL en entier
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
            // Envoi de l'identifiant pour l'interface visuelle
            res.json({ verified: true, username: passkey.user_id });
        }
    } catch (error) {
        console.error("Erreur détaillée login:", error);
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