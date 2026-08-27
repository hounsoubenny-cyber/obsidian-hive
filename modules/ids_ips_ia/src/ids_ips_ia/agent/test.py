#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Thu Jun 11 16:49:15 2026

@author: hounsousamuel
"""

import asyncio
import random
import time
from typing import List
from fastapi import FastAPI, WebSocket
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
import uvicorn

app = FastAPI(title="ShieldAI - Threat Monitor")

# --- MODÈLE DE DONNÉES ---
class LogEntry(BaseModel):
    timestamp: str
    source_ip: str
    event_type: str
    severity: str
    score: float

# --- BASE DE DONNÉES EN MÉMOIRE ---
logs_db: List[LogEntry] = []

# --- GÉNÉRATEUR DE LOGS (SIMULATION AGENT) ---
async def log_generator():
    event_types = ["SSH Login", "SQL Injection Attempt", "Port Scan", "Buffer Overflow", "File Access"]
    ips = ["192.168.1.10", "45.12.33.1", "10.0.0.5", "172.16.0.20"]
    
    while True:
        severity = random.choices(["LOW", "MEDIUM", "HIGH", "CRITICAL"], weights=[50, 30, 15, 5])[0]
        score = random.uniform(0.1, 0.9) if severity != "CRITICAL" else random.uniform(0.9, 1.0)
        
        new_log = LogEntry(
            timestamp=time.strftime("%H:%M:%S"),
            source_ip=random.choice(ips),
            event_type=random.choice(event_types),
            severity=severity,
            score=round(score, 2)
        )
        logs_db.append(new_log)
        if len(logs_db) > 50: logs_db.pop(0)
        await asyncio.sleep(2)

# --- ROUTES ---
@app.get("/")
async def get_dashboard():
    html_content = """
    <!DOCTYPE html>
    <html lang="fr">
    <head>
        <title>ShieldAI Monitor</title>
        <script src="https://cdn.tailwindcss.com"></script>
        <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    </head>
    <body class="bg-slate-900 text-white font-sans">
        <nav class="p-6 border-b border-slate-800 flex justify-between items-center">
            <h1 class="text-2xl font-bold text-cyan-400">🛡️ SHIELDAI <span class="text-white font-light">Monitor</span></h1>
            <div id="status" class="px-3 py-1 rounded-full bg-green-500/20 text-green-400 text-xs border border-green-500">SYSTEM ACTIVE</div>
        </nav>

        <div class="grid grid-cols-1 md:grid-cols-3 gap-6 p-6">
            <!-- Stats -->
            <div class="bg-slate-800 p-6 rounded-xl border border-slate-700 shadow-xl">
                <p class="text-slate-400 text-sm">Menaces Détectées</p>
                <p id="threat-count" class="text-4xl font-black mt-2">0</p>
            </div>
            <div class="bg-slate-800 p-6 rounded-xl border border-slate-700 shadow-xl">
                <p class="text-slate-400 text-sm">Score de Risque Moyen</p>
                <p id="avg-score" class="text-4xl font-black mt-2 text-yellow-400">0.0</p>
            </div>
            <div class="bg-slate-800 p-6 rounded-xl border border-slate-700 shadow-xl">
                <canvas id="miniChart" height="80"></canvas>
            </div>
        </div>

        <div class="p-6">
            <div class="bg-slate-800 rounded-xl border border-slate-700 shadow-xl overflow-hidden">
                <table class="w-full text-left">
                    <thead class="bg-slate-700/50 text-slate-300 text-xs uppercase">
                        <tr>
                            <th class="p-4">Time</th>
                            <th class="p-4">Source IP</th>
                            <th class="p-4">Event</th>
                            <th class="p-4">Severity</th>
                            <th class="p-4">AI Score</th>
                        </tr>
                    </thead>
                    <tbody id="log-table" class="text-sm">
                        <!-- Logs injectés ici -->
                    </tbody>
                </table>
            </div>
        </div>

        <script>
            const ws = new WebSocket("ws://localhost:8000/ws");
            let logsCount = 0;
            let totalScore = 0;

            ws.onmessage = (event) => {
                const data = JSON.parse(event.data);
                const table = document.getElementById('log-table');
                
                logsCount++;
                totalScore += data.score;

                // Mise à jour Stats
                document.getElementById('threat-count').innerText = logsCount;
                document.getElementById('avg-score').innerText = (totalScore / logsCount).toFixed(2);

                // Insertion Ligne
                const color = data.severity === 'CRITICAL' ? 'text-red-500 font-bold' : 
                              data.severity === 'HIGH' ? 'text-orange-400' : 'text-slate-300';
                
                const row = `<tr class="border-b border-slate-700 hover:bg-slate-700/30 transition">
                    <td class="p-4 text-slate-500">${data.timestamp}</td>
                    <td class="p-4 font-mono text-cyan-300">${data.source_ip}</td>
                    <td class="p-4">${data.event_type}</td>
                    <td class="p-4"><span class="${color}">${data.severity}</span></td>
                    <td class="p-4 font-bold text-cyan-500">${data.score}</td>
                </tr>`;
                
                table.insertAdjacentHTML('afterbegin', row);
            };
        </script>
    </body>
    </html>
    """
    return HTMLResponse(content=html_content)

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    last_idx = 0
    while True:
        if len(logs_db) > last_idx:
            for i in range(last_idx, len(logs_db)):
                await websocket.send_json(logs_db[i].dict())
            last_idx = len(logs_db)
        await asyncio.sleep(1)

# --- DÉMARRAGE ---
if __name__ == "__main__":
    loop = asyncio.get_event_loop()
    loop.create_task(log_generator())
    uvicorn.run(app, host="0.0.0.0", port=8000)