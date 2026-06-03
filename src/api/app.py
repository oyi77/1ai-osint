"""FastAPI service for async deep-scan jobs."""

from __future__ import annotations

import asyncio
import uuid
from datetime import datetime, timezone
from typing import Any

from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field

app = FastAPI(title="1ai-osint API", version="0.1.0")
_JOBS: dict[str, dict[str, Any]] = {}


class ScanRequest(BaseModel):
    target: str
    profile: str = Field(default="standard", pattern="^(fast|standard|deep)$")
    case_id: str = ""
    budget: float = Field(default=15.0, ge=0.0)


class ScanResponse(BaseModel):
    job_id: str
    status: str


@app.get("/health")
def health():
    return {"status": "ok", "service": "1ai-osint"}


@app.get("/v1/jobs")
def list_jobs():
    return [
        {
            "job_id": job_id,
            "status": job["status"],
            "target": job.get("target", "unknown"),
            "profile": job.get("profile", "unknown"),
            "budget": job.get("budget", 15.0),
            "created_at": job.get("created_at", datetime.now(timezone.utc).isoformat()),
            "error": job.get("error"),
        }
        for job_id, job in _JOBS.items()
    ]


@app.post("/v1/scan", response_model=ScanResponse)
async def create_scan(req: ScanRequest):
    job_id = f"job-{uuid.uuid4().hex[:12]}"
    _JOBS[job_id] = {
        "status": "queued",
        "target": req.target,
        "profile": req.profile,
        "case_id": req.case_id,
        "budget": req.budget,
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    asyncio.create_task(_run_job(job_id, req))
    return ScanResponse(job_id=job_id, status="queued")


@app.get("/v1/scan/{job_id}")
def get_scan(job_id: str):
    job = _JOBS.get(job_id)
    if not job:
        raise HTTPException(404, "job not found")
    return job


async def _run_job(job_id: str, req: ScanRequest) -> None:
    from src.modules.deep_scan.engine import DeepScanEngine
    from src.modules.deep_scan.exports import export_report
    from src.modules.deep_scan.report_generator import generate_intel_report_with_ai
    from src.modules.deep_scan.scan_profiles import resolve_scan_profile
    from src.investigations.case_manager import CaseManager

    _JOBS[job_id]["status"] = "running"
    try:
        prof = resolve_scan_profile(req.profile)
        engine = DeepScanEngine(
            profile_config=prof, modules=list(prof.modules), budget=req.budget
        )
        result = await engine.scan(req.target)
        intel = generate_intel_report_with_ai(result, use_ai=True)
        html = export_report(intel, fmt="html")
        js = export_report(intel, fmt="json")
        pdf = export_report(intel, fmt="pdf")
        _JOBS[job_id].update(
            {
                "status": "completed",
                "intel": js if isinstance(js, str) else js.decode(),
                "html": html if isinstance(html, str) else "",
            }
        )
        if req.case_id:
            CaseManager().save_run(
                req.case_id,
                req.target,
                result,
                intel,
                html=html if isinstance(html, str) else "",
                json_report=js if isinstance(js, str) else "",
                pdf_bytes=pdf if isinstance(pdf, bytes) else None,
            )
    except Exception as exc:
        _JOBS[job_id]["status"] = "failed"
        _JOBS[job_id]["error"] = str(exc)


@app.get("/ui", response_class=HTMLResponse)
@app.get("/", response_class=HTMLResponse)
def serve_ui():
    return """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>1ai-osint Control Center</title>
<link href="https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;600;700&display=swap" rel="stylesheet">
<script src="https://d3js.org/d3.v7.min.js"></script>
<style>
    :root {
        --bg-main: #0b0f19;
        --bg-card: rgba(17, 24, 39, 0.7);
        --border-color: rgba(255, 255, 255, 0.08);
        --text-primary: #f3f4f6;
        --text-secondary: #9ca3af;
        --accent-purple: #8b5cf6;
        --accent-blue: #3b82f6;
        --accent-gradient: linear-gradient(135deg, #6366f1, #a855f7);
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
        font-family: 'Outfit', sans-serif;
        background-color: var(--bg-main);
        color: var(--text-primary);
        min-height: 100vh;
        display: flex;
        flex-direction: column;
    }
    header {
        background: linear-gradient(to right, #111827, #0b0f19);
        border-bottom: 1px solid var(--border-color);
        padding: 16px 24px;
        display: flex;
        justify-content: space-between;
        align-items: center;
    }
    header h1 {
        font-size: 20px;
        font-weight: 700;
        background: var(--accent-gradient);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        letter-spacing: 0.5px;
    }
    .badge-premium {
        background: rgba(139, 92, 246, 0.2);
        border: 1px solid var(--accent-purple);
        color: #c084fc;
        padding: 2px 10px;
        border-radius: 9999px;
        font-size: 11px;
        font-weight: 600;
    }
    .dashboard-container {
        display: flex;
        flex: 1;
        overflow: hidden;
    }
    .sidebar {
        width: 320px;
        border-right: 1px solid var(--border-color);
        background-color: rgba(17, 24, 39, 0.4);
        padding: 20px;
        display: flex;
        flex-direction: column;
        gap: 20px;
        overflow-y: auto;
    }
    .main-view {
        flex: 1;
        padding: 20px;
        display: flex;
        flex-direction: column;
        gap: 20px;
        overflow-y: auto;
        position: relative;
    }
    .card {
        background: var(--bg-card);
        backdrop-filter: blur(12px);
        border: 1px solid var(--border-color);
        border-radius: 12px;
        padding: 20px;
    }
    .form-group {
        margin-bottom: 16px;
        display: flex;
        flex-direction: column;
        gap: 6px;
    }
    label {
        font-size: 12px;
        color: var(--text-secondary);
        font-weight: 600;
        text-transform: uppercase;
        letter-spacing: 0.5px;
    }
    input[type="text"], input[type="number"], select {
        background: rgba(255, 255, 255, 0.05);
        border: 1px solid var(--border-color);
        border-radius: 8px;
        padding: 10px 14px;
        color: var(--text-primary);
        font-family: inherit;
        font-size: 14px;
        outline: none;
        transition: border-color 0.2s;
    }
    input:focus, select:focus {
        border-color: var(--accent-purple);
    }
    .btn-submit {
        background: var(--accent-gradient);
        color: white;
        border: none;
        border-radius: 8px;
        padding: 12px;
        font-weight: 600;
        cursor: pointer;
        transition: opacity 0.2s;
    }
    .btn-submit:hover {
        opacity: 0.9;
    }
    .job-list {
        display: flex;
        flex-direction: column;
        gap: 10px;
    }
    .job-item {
        background: rgba(255, 255, 255, 0.03);
        border: 1px solid var(--border-color);
        border-radius: 8px;
        padding: 12px;
        cursor: pointer;
        display: flex;
        flex-direction: column;
        gap: 4px;
        transition: background 0.2s, border-color 0.2s;
    }
    .job-item:hover, .job-item.active {
        background: rgba(139, 92, 246, 0.08);
        border-color: var(--accent-purple);
    }
    .job-header {
        display: flex;
        justify-content: space-between;
        align-items: center;
    }
    .job-target {
        font-weight: 600;
        font-size: 14px;
        overflow: hidden;
        text-overflow: ellipsis;
        white-space: nowrap;
        max-width: 180px;
    }
    .status-badge {
        font-size: 10px;
        font-weight: 600;
        text-transform: uppercase;
        padding: 2px 6px;
        border-radius: 4px;
    }
    .status-completed { background: rgba(34, 197, 94, 0.2); color: #4ade80; }
    .status-running { background: rgba(59, 130, 246, 0.2); color: #60a5fa; animation: pulse 2s infinite; }
    .status-queued { background: rgba(234, 179, 8, 0.2); color: #facc15; }
    .status-failed { background: rgba(239, 68, 68, 0.2); color: #f87171; }
    
    .job-meta {
        font-size: 11px;
        color: var(--text-secondary);
        display: flex;
        justify-content: space-between;
    }
    
    .viewer-iframe {
        width: 100%;
        height: 600px;
        border: none;
        background: white;
        border-radius: 8px;
    }
    .no-selection {
        display: flex;
        flex-direction: column;
        justify-content: center;
        align-items: center;
        height: 400px;
        color: var(--text-secondary);
        gap: 12px;
    }
    .no-selection svg {
        stroke: var(--text-secondary);
        width: 48px;
        height: 48px;
    }
    .loading-pulse {
        display: flex;
        flex-direction: column;
        align-items: center;
        justify-content: center;
        height: 400px;
        gap: 16px;
    }
    .spinner {
        border: 4px solid rgba(255,255,255,0.1);
        width: 50px;
        height: 50px;
        border-radius: 50%;
        border-left-color: var(--accent-purple);
        animation: spin 1s linear infinite;
    }
    @keyframes spin {
        0% { transform: rotate(0deg); }
        100% { transform: rotate(360deg); }
    }
    @keyframes pulse {
        0%, 100% { opacity: 1; }
        50% { opacity: 0.6; }
    }
    .view-panel {
        display: none;
    }
    .view-panel.active {
        display: block;
    }
    .tab-btn {
        background: transparent;
        border: none;
        border-radius: 4px;
        color: var(--text-secondary);
        cursor: pointer;
        padding: 6px 12px;
        font-size: 12px;
        transition: background 0.2s, color 0.2s;
    }
    .tab-btn.active {
        background: rgba(255, 255, 255, 0.1);
        color: var(--text-primary);
    }
    .graph-node {
        cursor: pointer;
    }
    .graph-node circle {
        stroke: #111827;
        stroke-width: 2px;
        transition: r 0.2s, stroke-width 0.2s;
    }
    .graph-node:hover circle {
        stroke-width: 3px;
    }
    .graph-link {
        stroke: rgba(255, 255, 255, 0.15);
        stroke-opacity: 0.6;
        transition: stroke-opacity 0.2s;
    }
    .graph-link:hover {
        stroke-opacity: 1;
    }
    .tooltip {
        position: absolute;
        background: rgba(11, 15, 25, 0.9);
        backdrop-filter: blur(8px);
        border: 1px solid var(--border-color);
        padding: 8px 12px;
        border-radius: 6px;
        font-size: 11px;
        color: var(--text-primary);
        pointer-events: none;
        opacity: 0;
        transition: opacity 0.2s;
        z-index: 100;
    }
</style>
</head>
<body>
    <header>
        <h1>1ai-osint Control Center</h1>
        <div class="badge-premium">ZKIT Identity Correlation Node</div>
    </header>
    <div class="dashboard-container">
        <div class="sidebar">
            <div class="card">
                <form id="scanForm" onsubmit="startScan(event)">
                    <div class="form-group">
                        <label for="target">Target Identifier</label>
                        <input type="text" id="target" placeholder="Name, Email, NIK or Username" required>
                    </div>
                    <div class="form-group">
                        <label for="profile">Scan Profile</label>
                        <select id="profile">
                            <option value="standard" selected>Standard Profile</option>
                            <option value="fast">Fast Profile</option>
                            <option value="deep">Deep Profile</option>
                        </select>
                    </div>
                    <div class="form-group">
                        <label for="budget">Execution Budget</label>
                        <input type="number" id="budget" value="15.0" step="0.5" min="0">
                    </div>
                    <button type="submit" class="btn-submit">Launch Search</button>
                </form>
            </div>
            <div>
                <label style="display:block;margin-bottom:8px;">Active Operations</label>
                <div class="job-list" id="jobList">
                    <!-- Loaded dynamically -->
                </div>
            </div>
        </div>
        <div class="main-view" id="mainView">
            <div class="no-selection">
                <svg fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="1.5">
                  <path stroke-linecap="round" stroke-linejoin="round" d="M21 21l-5.197-5.197m0 0A7.5 7.5 0 105.196 5.196a7.5 7.5 0 0010.637 10.636z" />
                </svg>
                <p>Initialize or select an investigation job to load intelligence report</p>
            </div>
        </div>
    </div>
    
    <script>
        let selectedJobId = null;
        let jobTimer = null;

        async function fetchJobs() {
            try {
                const response = await fetch('/v1/jobs');
                const jobs = await response.json();
                renderJobList(jobs);
            } catch (err) {
                console.error("Failed to fetch jobs list", err);
            }
        }

        function renderJobList(jobs) {
            const listEl = document.getElementById('jobList');
            if (jobs.length === 0) {
                listEl.innerHTML = '<div style="font-size:12px;color:var(--text-secondary);text-align:center;padding:12px;">No scan logs found.</div>';
                return;
            }
            jobs.sort((a, b) => new Date(b.created_at) - new Date(a.created_at));
            listEl.innerHTML = jobs.map(job => {
                const badgeClass = `status-${job.status}`;
                const activeClass = job.job_id === selectedJobId ? 'active' : '';
                return `
                    <div class="job-item ${activeClass}" onclick="selectJob('${job.job_id}')">
                        <div class="job-header">
                            <span class="job-target" title="${job.target}">${job.target}</span>
                            <span class="status-badge ${badgeClass}">${job.status}</span>
                        </div>
                        <div class="job-meta">
                            <span>${job.profile.toUpperCase()} (Budget: ${job.budget})</span>
                            <span>${new Date(job.created_at).toLocaleTimeString()}</span>
                        </div>
                    </div>
                `;
            }).join('');
        }

        async function selectJob(jobId) {
            selectedJobId = jobId;
            clearInterval(jobTimer);
            fetchJobs(); // Update sidebar selection styling
            
            const mainView = document.getElementById('mainView');
            mainView.innerHTML = `
                <div class="loading-pulse">
                    <div class="spinner"></div>
                    <p>Fetching intelligence dossier...</p>
                </div>
            `;

            await pollJobStatus();
            // Start polling if not completed
            jobTimer = setInterval(pollJobStatus, 3000);
        }

        async function pollJobStatus() {
            if (!selectedJobId) return;
            try {
                const response = await fetch(`/v1/scan/${selectedJobId}`);
                const job = await response.json();
                const mainView = document.getElementById('mainView');

                if (job.status === 'completed') {
                    clearInterval(jobTimer);
                    window.currentIntel = JSON.parse(job.intel);
                    mainView.innerHTML = `
                        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:10px;">
                            <div>
                                <h3 style="font-size:18px;">Dossier for ${job.target}</h3>
                                <p style="font-size:12px;color:var(--text-secondary);">Profile: ${job.profile} | Budget: ${job.budget}</p>
                            </div>
                            <div style="display:flex;gap:10px;align-items:center;">
                                <div style="display:flex;background:rgba(255,255,255,0.05);padding:2px;border-radius:6px;border:1px solid var(--border-color);">
                                    <button onclick="switchView('dossier')" id="tab-dossier" class="tab-btn active">Dossier Report</button>
                                    <button onclick="switchView('graph')" id="tab-graph" class="tab-btn">ZKIT Graph Explorer</button>
                                </div>
                                <button onclick="downloadJSON()" class="btn-submit" style="padding:6px 12px;font-size:12px;background:rgba(255,255,255,0.05);border:1px solid var(--border-color);">JSON Report</button>
                            </div>
                        </div>
                        <div id="dossierPanel" class="view-panel active">
                            <iframe class="viewer-iframe" srcdoc="${escapeHtml(job.html)}"></iframe>
                        </div>
                        <div id="graphPanel" class="view-panel" style="position:relative;">
                            <div id="graphContainer" style="width: 100%; height: 600px; background: rgba(0,0,0,0.2); border-radius: 8px; border: 1px solid var(--border-color); overflow: hidden; position: relative;"></div>
                            <div id="graphTooltip" class="tooltip"></div>
                            <div style="position:absolute; bottom:12px; left:12px; background:rgba(11,15,25,0.85); backdrop-filter:blur(8px); padding:10px; border-radius:6px; border:1px solid var(--border-color); font-size:11px; display:flex; flex-direction:column; gap:6px; pointer-events:none; z-index:10;">
                              <div style="display:flex; align-items:center; gap:6px;"><span style="width:10px; height:10px; border-radius:50%; background:#f87171; display:inline-block;"></span> Seed Target</div>
                              <div style="display:flex; align-items:center; gap:6px;"><span style="width:10px; height:10px; border-radius:50%; background:#60a5fa; display:inline-block;"></span> Email Address</div>
                              <div style="display:flex; align-items:center; gap:6px;"><span style="width:10px; height:10px; border-radius:50%; background:#34d399; display:inline-block;"></span> Crypto Wallet</div>
                              <div style="display:flex; align-items:center; gap:6px;"><span style="width:10px; height:10px; border-radius:50%; background:#facc15; display:inline-block;"></span> Username / Handle</div>
                              <div style="display:flex; align-items:center; gap:6px;"><span style="width:10px; height:10px; border-radius:50%; background:#c084fc; display:inline-block;"></span> Phone Number</div>
                              <div style="display:flex; align-items:center; gap:6px;"><span style="width:10px; height:10px; border-radius:50%; background:#fb923c; display:inline-block;"></span> Social Media Platform</div>
                            </div>
                        </div>
                    `;
                } else if (job.status === 'running' || job.status === 'queued') {
                    mainView.innerHTML = `
                        <div class="loading-pulse">
                            <div class="spinner"></div>
                            <p style="font-size:16px;font-weight:600;">Operation in progress...</p>
                            <p style="font-size:12px;color:var(--text-secondary);">Recursively pivoting targets and resolving identities. Status: ${job.status.toUpperCase()}</p>
                        </div>
                    `;
                } else if (job.status === 'failed') {
                    clearInterval(jobTimer);
                    mainView.innerHTML = `
                        <div class="card" style="border-color:#f87171;background:rgba(239,68,68,0.05);padding:24px;text-align:center;">
                            <h3 style="color:#f87171;font-size:18px;margin-bottom:8px;">Search Operation Failed</h3>
                            <p style="font-size:14px;color:var(--text-secondary);">${job.error || 'Unknown error occurred'}</p>
                        </div>
                    `;
                }
            } catch (err) {
                console.error(err);
            }
        }

        async function startScan(e) {
            e.preventDefault();
            const target = document.getElementById('target').value;
            const profile = document.getElementById('profile').value;
            const budget = parseFloat(document.getElementById('budget').value) || 0;

            try {
                const response = await fetch('/v1/scan', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ target, profile, budget })
                });
                const res = await response.json();
                if (res.job_id) {
                    document.getElementById('target').value = '';
                    selectJob(res.job_id);
                }
            } catch (err) {
                alert("Failed to initialize scan.");
            }
        }

        async function downloadJSON() {
            if (!selectedJobId) return;
            try {
                const response = await fetch(`/v1/scan/${selectedJobId}`);
                const job = await response.json();
                const blob = new Blob([JSON.stringify(JSON.parse(job.intel), null, 2)], { type: 'application/json' });
                const url = URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                a.download = `intel_report_${job.target.replace(/\\s+/g, '_')}.json`;
                document.body.appendChild(a);
                a.click();
                document.body.removeChild(a);
            } catch (err) {
                alert("Failed to export JSON");
            }
        }

        function escapeHtml(string) {
            return string
                .replace(/&/g, "&amp;")
                .replace(/</g, "&lt;")
                .replace(/>/g, "&gt;")
                .replace(/"/g, "&quot;")
                .replace(/'/g, "&#039;");
        }

        function switchView(view) {
            document.querySelectorAll('.view-panel').forEach(p => p.classList.remove('active'));
            document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
            
            if (view === 'dossier') {
                document.getElementById('dossierPanel').classList.add('active');
                document.getElementById('tab-dossier').classList.add('active');
            } else if (view === 'graph') {
                document.getElementById('graphPanel').classList.add('active');
                document.getElementById('tab-graph').classList.add('active');
                if (window.currentIntel && window.currentIntel.identity_graph) {
                    setTimeout(() => drawGraph(window.currentIntel.identity_graph), 100);
                }
            }
        }

        function drawGraph(graphData) {
            const container = document.getElementById('graphContainer');
            container.innerHTML = '';

            const width = container.clientWidth || 800;
            const height = 600;

            const svg = d3.create("svg")
                .attr("width", "100%")
                .attr("height", height)
                .attr("viewBox", `0 0 ${width} ${height}`)
                .attr("style", "max-width: 100%; height: auto;");

            const tooltip = document.getElementById('graphTooltip');
            const g = svg.append("g");
            
            svg.call(d3.zoom()
                .extent([[0, 0], [width, height]])
                .scaleExtent([0.1, 4])
                .on("zoom", ({transform}) => {
                    g.attr("transform", transform);
                }));

            const nodes = graphData.nodes.map(d => Object.create(d));
            const links = graphData.edges.map(d => ({
                source: d.source_id,
                target: d.target_id,
                relationship: d.relationship,
                weight: d.weight
            }));

            const simulation = d3.forceSimulation(nodes)
                .force("link", d3.forceLink(links).id(d => d.id).distance(120))
                .force("charge", d3.forceManyBody().strength(-250))
                .force("center", d3.forceCenter(width / 2, height / 2))
                .force("collision", d3.forceCollide().radius(35));

            const link = g.append("g")
                .selectAll("line")
                .data(links)
                .join("line")
                .attr("class", "graph-link")
                .attr("stroke-width", d => Math.max(1.5, d.weight * 4.5));

            const colors = {
                "name": "#f87171",
                "email": "#60a5fa",
                "crypto": "#34d399",
                "username": "#facc15",
                "phone": "#c084fc",
                "social": "#fb923c",
                "default": "#9ca3af"
            };

            function drag(simulation) {
                function dragstarted(event, d) {
                    if (!event.active) simulation.alphaTarget(0.3).restart();
                    d.fx = d.x;
                    d.fy = d.y;
                }
                function dragged(event, d) {
                    d.fx = event.x;
                    d.fy = event.y;
                }
                function dragended(event, d) {
                    if (!event.active) simulation.alphaTarget(0);
                    d.fx = null;
                    d.fy = null;
                }
                return d3.drag()
                    .on("start", dragstarted)
                    .on("drag", dragged)
                    .on("end", dragended);
            }

            const node = g.append("g")
                .selectAll("g")
                .data(nodes)
                .join("g")
                .attr("class", "graph-node")
                .call(drag(simulation))
                .on("mouseover", (event, d) => {
                    tooltip.style.opacity = 1;
                    tooltip.innerHTML = `
                        <strong>Label:</strong> ${escapeHtml(d.label)}<br>
                        <strong>Type:</strong> ${escapeHtml(d.type.toUpperCase())}<br>
                        <strong>Confidence:</strong> ${(d.weight * 100).toFixed(0)}%
                    `;
                })
                .on("mousemove", (event) => {
                    const rect = container.getBoundingClientRect();
                    tooltip.style.left = (event.clientX - rect.left + 15) + "px";
                    tooltip.style.top = (event.clientY - rect.top + 15) + "px";
                })
                .on("mouseout", () => {
                    tooltip.style.opacity = 0;
                })
                .on("dblclick", (event, d) => {
                    document.getElementById('target').value = d.label;
                    document.getElementById('target').focus();
                    alert(`Target pivot set to: ${d.label}`);
                });

            node.append("circle")
                .attr("r", d => d.id === "target" ? 18 : 12)
                .attr("fill", d => colors[d.type] || colors["default"])
                .style("filter", "drop-shadow(0px 0px 6px rgba(255,255,255,0.15))");

            node.append("text")
                .attr("x", 0)
                .attr("y", d => d.id === "target" ? 28 : 22)
                .attr("text-anchor", "middle")
                .text(d => d.label)
                .attr("fill", "#f3f4f6")
                .attr("font-size", "10px")
                .attr("font-weight", d => d.id === "target" ? "700" : "500")
                .style("pointer-events", "none")
                .style("text-shadow", "0 1px 3px rgba(0,0,0,0.9)");

            simulation.on("tick", () => {
                link
                    .attr("x1", d => d.source.x)
                    .attr("y1", d => d.source.y)
                    .attr("x2", d => d.target.x)
                    .attr("y2", d => d.target.y);

                node
                    .attr("transform", d => `translate(${d.x}, ${d.y})`);
            });

            container.appendChild(svg.node());
        }

        // Auto-refresh jobs on load
        fetchJobs();
        setInterval(fetchJobs, 5000);
    </script>
</body>
</html>
"""


# --- ZKIT React Dashboard Endpoints (Migrated from src/api.py) ---
from fastapi.middleware.cors import CORSMiddleware  # noqa: E402

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class ReactScanRequest(BaseModel):
    target: str
    fast: bool = True
    max_iterations: int = 5


class ReactJobResponse(BaseModel):
    job_id: str
    status: str
    target: str


async def _run_deep_scan_job_react(
    job_id: str, target: str, fast: bool, max_iterations: int
):
    from src.modules.deep_scan.engine import DeepScanEngine

    _JOBS[job_id]["status"] = "running"
    try:
        engine = DeepScanEngine(max_iterations=max_iterations, fast=fast)
        result = await engine.scan(target)
        _JOBS[job_id]["status"] = "completed"
        _JOBS[job_id]["result"] = result.to_dict()
    except Exception as e:
        _JOBS[job_id]["status"] = "failed"
        _JOBS[job_id]["error"] = str(e)


@app.post("/api/scan", response_model=ReactJobResponse)
async def start_scan_react(
    request: ReactScanRequest, background_tasks: __import__("fastapi").BackgroundTasks
):
    job_id = str(uuid.uuid4())
    _JOBS[job_id] = {
        "job_id": job_id,
        "target": request.target,
        "status": "pending",
        "started_at": datetime.now(timezone.utc).isoformat(),
        "result": None,
        "error": None,
    }
    background_tasks.add_task(
        _run_deep_scan_job_react,
        job_id,
        request.target,
        request.fast,
        request.max_iterations,
    )
    return ReactJobResponse(job_id=job_id, status="pending", target=request.target)


@app.get("/api/scan/{job_id}")
async def get_scan_status_react(job_id: str):
    if job_id not in _JOBS:
        raise HTTPException(status_code=404, detail="Job not found")
    return _JOBS[job_id]
