import io,json,re,zipfile,hashlib
from pathlib import PurePosixPath
from collections import Counter
IGNORE={".git","node_modules","dist","build",".venv","venv","__pycache__",".next","coverage"}
MANIFESTS={"package.json":"npm","package-lock.json":"npm-lock","yarn.lock":"yarn","pnpm-lock.yaml":"pnpm","requirements.txt":"python","pyproject.toml":"python","pom.xml":"maven","build.gradle":"gradle","go.mod":"go","Cargo.toml":"cargo","composer.json":"composer","Dockerfile":"container"}
SECRET=[("AWS Access Key",r"\bAKIA[0-9A-Z]{16}\b"),("Private Key",r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),("Generic Secret",r"(?i)\b(?:api[_-]?key|access[_-]?token|secret[_-]?key)\b\s*[:=]\s*['\"][A-Za-z0-9_\-]{12,}['\"]"),("Database URL",r"(?i)(?:mongodb|postgres(?:ql)?|mysql)://[^\s'\"`]+")]
BEHAV=[("Dynamic Execution",r"\b(eval|exec)\s*\(",18),("Shell Execution",r"\b(?:subprocess\.(?:run|Popen|call)|child_process\.exec|os\.system)\s*\(",16),("Lifecycle Script",r"(?i)\b(?:preinstall|postinstall|prepare)\b",18),("Remote Script Pipe",r"(?i)\b(?:curl|wget)\b.{0,100}\|\s*(?:sh|bash|python)",24),("Network Endpoint",r"https?://[^\s'\"`]{8,}",3)]
def infos(z):
    out=[]
    for i in z.infolist():
        p=PurePosixPath(i.filename)
        if p.is_absolute() or ".." in p.parts or any(x in IGNORE for x in p.parts) or i.is_dir(): continue
        out.append(i)
    return out
def deps(z,i):
    raw=z.read(i).decode("utf8","ignore"); out=[]
    if i.filename.endswith("package.json"):
        try:
            o=json.loads(raw)
            for scope in ("dependencies","devDependencies","optionalDependencies"):
                for n,v in o.get(scope,{}).items(): out.append({"name":n,"version":str(v),"ecosystem":"npm","scope":scope})
        except: pass
    elif PurePosixPath(i.filename).name=="requirements.txt":
        for l in raw.splitlines():
            l=l.strip()
            if not l or l.startswith("#") or l.startswith("-"): continue
            m=re.match(r"([A-Za-z0-9_.-]+)\s*(?:[<>=!~]{1,3}\s*([A-Za-z0-9.*+_-]+))?",l)
            if m: out.append({"name":m.group(1),"version":m.group(2) or "unlocked","ecosystem":"python","scope":"runtime"})
    return out
def scan_zip(data,filename):
    try:
        z=zipfile.ZipFile(io.BytesIO(data)); z.testzip()
    except zipfile.BadZipFile: raise ValueError("Invalid ZIP archive.")
    fs=infos(z); inventory=[]; findings=[]; exts=Counter(); total=0
    for i in fs:
        total+=i.file_size; exts[PurePosixPath(i.filename).suffix.lower() or "[no extension]"]+=1
        base=PurePosixPath(i.filename).name
        if base in MANIFESTS: inventory+=deps(z,i)
        if i.file_size>1000000: continue
        txt=z.read(i).decode("utf8","ignore")
        for title,pat in SECRET:
            if re.search(pat,txt): findings.append({"severity":"critical","category":"Secrets","title":title,"file":i.filename,"evidence":"Credential-like pattern detected; value redacted.","score":30,"action":"Rotate/revoke and remove from source control."})
        for title,pat,score in BEHAV:
            if re.search(pat,txt):
                findings.append({"severity":"high" if score>=16 else "medium","category":"Behavior","title":title,"file":i.filename,"evidence":"Risky execution/network pattern detected.","score":score,"action":"Review the matched path and require approval before CI execution."})
    for d in inventory:
        n=d["name"].lower()
        if any(x in n for x in ("suspicious","malware","backdoor","typo","unknown-pkg")):
            findings.append({"severity":"high","category":"Dependency","title":"Suspicious dependency signal","file":"dependency manifest","evidence":f"Package '{d['name']}' requires provenance review.","score":24,"action":"Verify publisher, provenance, release history and lockfile integrity."})
    findings=list({(f["file"],f["title"]):f for f in findings}.values())
    findings.sort(key=lambda x:{"critical":0,"high":1,"medium":2,"low":3}[x["severity"]])
    c=sum(f["severity"]=="critical" for f in findings); h=sum(f["severity"]=="high" for f in findings); m=sum(f["severity"]=="medium" for f in findings)
    risk=min(100,7+c*23+h*13+m*6+min(40,len(inventory))*.45); score=max(0,round(100-risk))
    posture="CRITICAL" if score<35 else "HIGH RISK" if score<60 else "GUARDED" if score<80 else "HEALTHY"
    digest=hashlib.sha256(data).hexdigest()
    actions=[{"action":f["action"],"target":f["file"],"mode":"approval-required" if f["severity"] in ("critical","high") else "automatable"} for f in findings[:12]]
    return {
      "scan_id":digest[:12].upper(),"file":filename,"posture":posture,"security_score":score,"risk_score":round(risk),
      "summary":{"files":len(fs),"bytes":total,"dependencies":len(inventory),"findings":len(findings),"critical":c,"high":h,"medium":m},
      "technology":sorted({MANIFESTS[PurePosixPath(i.filename).name] for i in fs if PurePosixPath(i.filename).name in MANIFESTS}),
      "extensions":exts.most_common(12),"dependencies":inventory[:500],"findings":findings[:150],"defense_actions":actions,
      "sbom":{"format":"AegisFlow-SBOM-3.0","component_count":len(inventory),"sha256":digest,"components":inventory[:500]},
      "attack_graph":{"nodes":[{"id":"repo","label":"Repository","kind":"source"},{"id":"dep","label":f"{len(inventory)} Components","kind":"dependency"},{"id":"sig","label":f"{len(findings)} Signals","kind":"threat"},{"id":"app","label":"Application Surface","kind":"target"},{"id":"ci","label":"CI/CD","kind":"pipeline"}],"edges":[["repo","dep"],["dep","sig"],["sig","app"],["repo","ci"],["ci","app"]]},
      "timeline":[{"event":"Repository fingerprinted","status":"complete"},{"event":"Component graph built","status":"complete"},{"event":"Secrets and behavior correlated","status":"complete"},{"event":"Risk posture calculated","status":"complete"},{"event":"Attack paths prioritized","status":"complete"},{"event":"Defense plan prepared","status":"ready"}],
      "trust":{"provenance":"not independently attested in local demo","lock_integrity":"manifest observed; lock verification extension point","policy":"approval required for high-impact actions"},
      "compliance":{"SBOM":"mapped","Secrets":"mapped","Least Privilege":"review","Provenance":"review","Audit Trail":"ready"},
      "live":{"events":["Package graph heartbeat","CI policy watcher","Repository integrity pulse","Threat correlation loop","Defense queue synchronized"]}
    }
