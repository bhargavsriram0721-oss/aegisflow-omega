# AegisFlow OMEGA
## AI-Powered Autonomous Software Supply-Chain Defense — SIH 2026

A multi-page, futuristic defensive security console.

### Modules
1. Command Center
2. Live Detector
3. Repository X-Ray
4. Dependency DNA
5. Secret Sentinel
6. Behavior Lab
7. Threat Intelligence
8. Attack Path
9. Provenance & Trust
10. SBOM Forge
11. CI/CD Guardian
12. Risk Simulator
13. Remediation Center
14. Evidence Vault
15. Compliance Matrix
16. AI Security Copilot
17. Defense Autopilot

### Run backend
```bash
cd backend
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
python -m uvicorn app.main:app --port 8000
```

### Run frontend
```bash
cd frontend
npm install
npm run dev
```

Open http://localhost:5173

### Demo
Zip the included `demo-repository` and upload it. The scanner analyzes the ZIP locally and returns:
- repository inventory
- dependency inventory
- secret-like patterns (redacted)
- risky execution/lifecycle/network patterns
- deterministic risk score
- SBOM-style component list
- attack graph
- defense actions
- timeline

### Safety
This is a defensive prototype for authorized repositories. It does not exploit vulnerabilities, execute uploaded code, or attack external systems. High-impact remediation is represented as an approval-gated plan rather than silently changing production.
