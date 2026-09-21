const express = require('express');
const si = require('systeminformation');

const app = express();

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
            network: net[0] ? (net[0].tx_sec + net[0].rx_sec) / 1024 / 1024 : 0 // Conversion en MB/s
        });
    } catch (error) {
        res.status(500).json({ error: 'Erreur de lecture' });
    }
});

app.listen(3000, () => console.log('API prête sur le port 3000'));