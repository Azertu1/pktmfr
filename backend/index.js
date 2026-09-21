const express = require('express');
const cors = require('cors');
const si = require('systeminformation'); // 1. Importer la bibliothèque

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json());

// Route de test (Corrigé res.json au lieu de json)
app.get('/api', (req, res) => {
    res.json({ message: "Node.js fonctionne" });
});

// 2. Ajouter la route pour récupérer les métriques du serveur hôte
app.get('/api/metrics', async (req, res) => {
    try {
        const load = await si.currentLoad();
        const mem = await si.mem();

        res.json({
            cpu: Math.round(load.currentLoad), // Pourcentage d'utilisation global du CPU
            memory: {
                total: mem.total,
                used: mem.used,
                percent: Math.round((mem.used / mem.total) * 100)
            }
        });
    } catch (error) {
        console.error("Erreur lors de la récupération des métriques :", error);
        res.status(500).json({ error: "Impossible de récupérer les métriques du serveur" });
    }
});

app.listen(PORT, () => {
    console.log(`Serveur démarré sur le port ${PORT}`);
});