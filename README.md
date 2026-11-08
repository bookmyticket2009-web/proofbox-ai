# ProofBox AI

ProofBox AI is a security-first coding agent. A user describes a task in plain English, Vultr Serverless Inference writes the Python code, ProofBox AI checks it without running it, and the user can then run it inside a contained, network-isolated sandbox on a Vultr Cloud Compute server. Every step is saved to an audit history.

Built for the **Vultr Agent Rush**, **Blast Radius Zero** track: the agent does real work (writing and running code), and every action that executes code stays inside a sandbox on Vultr.

---

## Vultr services used

| Vultr service | What ProofBox AI uses it for |
|---|---|
| **Serverless Inference** | Every code-generation request goes to Vultr's OpenAI-compatible endpoint (`https://api.vultrinference.com/v1`), using the `deepseek-v4.1-flash-1017` model. |
| **Cloud Compute (sandbox)** | A dedicated Debian 13 server in Atlanta runs all user code. It is reached over SSH with key authentication only. |
| **Reserved IPv4** | A static public address for the sandbox server, so the hosted dashboard can reach it. |

**Where the web app runs.** The dashboard and API run on a Vultr Cloud Compute instance in Atlanta, served at `http://64.177.41.171:8000` on a reserved IPv4 address. They run as a `systemd` service, which restarts on boot, under a separate `proofbox-web` system user. The sandbox runs on a second Vultr instance, the same as above. Both instances use Debian 13.

---

## How it works

```
 User (browser)
     |
     v
 Dashboard + FastAPI backend (Vultr Cloud Compute)
     |                    |                         |
     | generate code      | verify code             | run code over SSH
     v                    v (no execution)         v
 Vultr Serverless     Static checks            Vultr sandbox server
 Inference            (AST parse + patterns)   - non-root user, no sudo
                                               - no outbound internet
                                               - time, memory, output limits
                                               - temp files deleted after run
                                                     |
                                                     v
                                            Result saved to job history
```

1. The user describes a task. Vultr Serverless Inference writes Python for it.
2. ProofBox AI checks the code: Python's parser runs first, then pattern checks for dangerous calls, risky imports, and hardcoded secrets. Nothing executes at this step.
3. The user reads the code and clicks **Run in sandbox**. Generated code is never run automatically.
4. The sandbox runs the code under its limits and returns stdout, stderr, exit code, duration, and cleanup status.
5. Every generation, check, scan, and run is saved to the audit history, where each run can be inspected with its code and output.

---

## Agent behaviour

ProofBox AI is a **human-supervised** execution agent. The model proposes code and the sandbox runs it, but a person reviews the code and clicks each run. The agent never executes code on its own. This is deliberate: the containment layer is what makes running AI-written code acceptable, and the human click is a second control.

Tasks the agent can carry out end to end:
- Write a Python program for a described task, then check it.
- Run it in the sandbox and report the real output and any errors.
- Use the Python standard library and a set of installed packages (see below) inside the sandbox.

---

## Containment controls

Each sandbox run is limited by the runner on the server:

| Control | Limit |
|---|---|
| Run as user | `sandbox` (no sudo, no shared secrets on the machine) |
| Internet access | Blocked by firewall for the sandbox user, tested at setup and by the readiness check |
| Time | 1 to 30 seconds per run, then the process group is killed |
| Memory | 1.5 GB address space |
| Output | 64 KB shown per stream; larger output stops the process |
| Processes | 32 per run, which stops fork bombs |
| Files | 1 MB output file size limit |
| Cleanup | Temporary folder deleted after every run; the result reports whether cleanup was confirmed |
| Input | Code travels to the server on stdin as JSON, never inside a shell command |

**Readiness check.** The dashboard's **Execution environment** card shows **READY** only when a live check confirms that the connection works, cleanup succeeds, and code on the server cannot reach the internet.

**Static checks are not a guarantee.** They can miss problems and flag safe code. A clean result doesn't prove that code is secure.

---

## What works today

| Feature | Status | Notes |
|---|---|---|
| Code generation | Working | Vultr Serverless Inference (default), or Ollama Cloud |
| Static verification | Working | Python syntax check first, then pattern rules; never executes code |
| Sandbox execution | Working | Dedicated Vultr server with the controls above |
| Sandbox readiness check | Working | Connection, cleanup, and network isolation are tested live |
| Installed libraries in the sandbox | Working | Standard library plus the packages listed below |
| GitHub repository scanner | Working | Pins a commit, redacts secrets, streams findings live, can be stopped |
| Job history | Working | Local SQLite database; every run is saved with its code and result |
| Export | Working | JSON and SARIF 2.1.0 downloads |

**Not built yet:** "Fix with AI", diff scanning, dependency vulnerability checks, finding suppression, PDF reports, automatic destruction of the sandbox server, and hosting the dashboard on Vultr.

---

## Libraries available in the sandbox

The sandbox server has these packages installed system-wide, so the sandbox user can import them but can't change them:

`numpy`, `pandas`, `scipy`, `scikit-learn`, `matplotlib`, `Pillow`, `beautifulsoup4`, `lxml`, `sympy`, `networkx`, `requests`, `PyYAML`, `python-dateutil`, `SQLAlchemy`, `openpyxl`

Large libraries run only within the 1.5 GB memory limit, so very heavy models won't fit.

---

## Project structure

```
proofbox-ai/
├── backend/
│   ├── app/
│   │   ├── main.py                    # API routes
│   │   ├── db.py                      # SQLite job history
│   │   ├── sandbox/runner.py          # Runs on the sandbox server
│   │   └── services/
│   │       ├── ai_service.py          # Vultr Serverless Inference and Ollama clients
│   │       ├── ai_status.py           # AI provider status check
│   │       ├── export_service.py      # JSON and SARIF export
│   │       ├── github_service.py      # Repository scanner
│   │       ├── sandbox_service.py     # Sandbox client (SSH)
│   │       └── verification_service.py
│   ├── requirements.txt
│   └── test_ollama.py
├── deploy/
│   └── setup_sandbox_vm.sh            # One-time setup for the sandbox server
├── frontend/
│   ├── index.html                     # Dashboard
│   └── app.js                         # Dashboard behaviour
├── tests/
│   ├── test_ai_service.py
│   ├── test_github_scanner_v2.py
│   └── test_sandbox.py
├── .env.example
├── .gitignore
└── README.md
```

---

## Setup

### Requirements
- Python 3.12 or newer (developed on 3.13)
- A Vultr Serverless Inference key and model name
- A Vultr Cloud Compute server for the sandbox (optional for the other features)

### 1. Create your environment file

Copy `.env.example` to `.env` and fill in the values:

```env
APP_NAME=ProofBox AI
APP_ENV=development

AI_PROVIDER=vultr
VULTR_INFERENCE_API_KEY=your-key-here
VULTR_INFERENCE_BASE_URL=https://api.vultrinference.com/v1
VULTR_INFERENCE_MODEL=deepseek-v4.1-flash-1017

SANDBOX_HOST=your-sandbox-ip-or-ipv6
SANDBOX_USER=sandbox
SANDBOX_KEY_PATH=C:/Users/you/.ssh/id_ed25519
SANDBOX_KNOWN_HOSTS_FILE=
```

`AI_PROVIDER=ollama` switches to Ollama Cloud instead; it then needs `OLLAMA_API_KEY`, `OLLAMA_BASE_URL`, and `OLLAMA_MODEL`.

Never commit `.env`. It is excluded by `.gitignore`.

### 2. Install and run (Windows PowerShell)

```powershell
cd proofbox-ai
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r backend\requirements.txt
python -m uvicorn app.main:app --app-dir backend --reload --port 8000
```

### 2. Install and run (macOS / Linux)

```bash
cd proofbox-ai
python3 -m venv .venv
source .venv/bin/activate
pip install -r backend/requirements.txt
python -m uvicorn app.main:app --app-dir backend --reload --port 8000
```

Open **http://127.0.0.1:8000**. Load the page through the server, not by opening `index.html` directly.

Check the AI provider at `http://127.0.0.1:8000/api/ai/status`. The `provider` field should read `vultr`.

### 3. Set up the sandbox server (optional)

1. Create a Debian 13 Cloud Compute instance on Vultr with at least 2 GB of memory, and add your SSH public key.
2. Copy `runner.py` and the setup script to the server, then run the setup as root:

   ```bash
   sudo bash setup_sandbox_vm.sh /root/runner.py
   ```

   The script creates the `sandbox` user, installs the runner, blocks the sandbox user's internet access, and self-tests the block. It ends with `Self-test passed`.
3. Add your public key to `/home/sandbox/.ssh/authorized_keys` for the `sandbox` user.
4. Install the packages (optional, see the list above) with `apt-get install`.
5. Set the `SANDBOX_*` variables in `.env` and restart. The Execution environment card should show **READY**.

---

## Tests

From the project root:

```bash
python tests/test_ai_service.py
python tests/test_sandbox.py
python tests/test_github_scanner_v2.py
```

- **AI service:** request format, model selection, key handling, and status reporting, using fake HTTP responses.
- **Sandbox:** input validation, the SSH protocol, the readiness check, and the runner's safety controls. The runner tests run on Linux with a non-root user and are skipped on Windows.
- **Scanner:** detection, redaction, cancellation, and SARIF output, using fixtures in place of GitHub.

---

## Roadmap

1. Serve the dashboard over HTTPS with a domain name, instead of plain HTTP on port 8000.
2. Connect generation directly to the sandbox, so the agent can write, check, and run code in one flow.
3. Add "Fix with AI", which re-checks the patched code before showing it.
4. Add diff scanning, dependency checks, and finding suppression with a required reason.
5. Destroy the sandbox server automatically through the Vultr API after each session.

---

## Licence

Coursework project for the Vultr Agent Rush hackathon. Add a licence before accepting outside contributions.
