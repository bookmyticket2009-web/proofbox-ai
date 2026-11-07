# ProofBox AI

ProofBox AI is a security-focused coding platform. It generates Python code with an AI model, checks code for risky patterns before anything runs, scans public GitHub repositories for leaked secrets and dangerous code, and runs code on a disposable, network-isolated Linux server on Vultr.

It is built for the Vultr Agent Rush **Blast Radius Zero** track: every action that runs code stays inside a contained sandbox on Vultr.

---

## What works today

| Feature | Status | Notes |
|---|---|---|
| AI code generation | Working | Uses Ollama Cloud (`gpt-oss:120b`). Needs an API key. |
| Static verification | Working | Python AST checks for syntax, dangerous calls, and risky imports. Never executes code. |
| GitHub repository scanner | Working | Pins a commit SHA, scans up to 500 files, redacts secrets, streams live findings, and can be stopped with partial results. |
| Remote sandbox | Working | Runs Python on a Vultr VM as a non-root user, with no internet access, time, memory, output, and process limits, and cleanup after each run. |
| Sandbox readiness check | Working | Confirms connection, cleanup, and that the sandbox cannot reach the internet. |
| Job history | Working | Every generation, verification, scan, and sandbox run is saved in a local SQLite database. |
| Export | Working | Scan and job results can be downloaded as JSON or SARIF 2.1.0. |

**Not built yet:** "Fix with AI", diff scanning between commits, dependency vulnerability checks, finding suppression, PDF reports, automatic destruction of the sandbox server, and hosting the web app on Vultr.

---

## Security model

ProofBox AI is designed so that untrusted code never runs on your own machine.

- **Static checks read code, they do not run it.** The verifier and the GitHub scanner only analyse text.
- **Generated code is never run automatically.** A user must click **Run in sandbox**.
- **The sandbox is a separate Linux server.** Code runs there as an unprivileged `sandbox` user with no sudo.
- **Code never reaches a shell command.** It travels to the server on standard input as JSON.
- **Resource limits** on each run: CPU time, memory (256 MB), file size (1 MB of output), process count (32), and a timeout (1–30 seconds).
- **No internet access for the sandbox user.** The setup script blocks outbound traffic for that user with a firewall rule and tests that the block works.
- **Secrets stay out of the browser.** API keys are read from `.env` on the server only.
- **Scan output is redacted.** Detected secrets are masked before they are stored or shown.

**Limits to be aware of:** this is a first-pass pattern scanner, not a complete SAST engine or malware detector. A clean result does not prove that a repository or program is safe. Containers and VMs share kernels with their host, so the sandbox relies on the VM boundary plus the controls above.

---

## How Vultr is used

**Vultr Cloud Compute (sandbox server).** Every piece of code that ProofBox AI runs executes on a Vultr Cloud Compute instance, not on the machine running the dashboard. The instance is a Shared CPU plan running Debian 13 in the Atlanta region. It is connected to the backend over SSH with key authentication only.

What the instance does for the project:

- **Isolated execution.** Code is run by an unprivileged `sandbox` user with no sudo access and no shared secrets on the machine.
- **Network containment.** An iptables rule blocks all outbound traffic from the `sandbox` user. The setup script tests this by trying to reach the internet from inside the sandbox and fails if the connection succeeds.
- **Per-run limits.** Each run has a timeout, a memory cap, an output cap, a process cap, and a file-size cap. The run's temporary folder is deleted afterwards, and the result reports whether cleanup was confirmed.
- **Readiness checks.** The dashboard's **Execution environment** card reports **READY** only when connection, cleanup, and network isolation all pass in a live check.

The sandbox setup is a single script, [`deploy/setup_sandbox_vm.sh`](deploy/setup_sandbox_vm.sh), which runs once on a new instance.

**What is not yet on Vultr.** The dashboard and API run on the developer's machine. Hosting them on a Vultr instance is planned. AI generation uses Ollama Cloud, not Vultr Serverless Inference. Vultr's API is not yet used to create or destroy sandbox instances automatically.

---

## The agent and what it does

ProofBox AI is a human-supervised execution agent. The workflow is:

1. The user describes a task. Ollama Cloud writes Python code for it.
2. ProofBox AI checks the code statically, without running it, and reports any risky patterns.
3. The user reviews the code and clicks **Run in sandbox**.
4. The code runs on the Vultr instance under the containment controls above.
5. The stdout, stderr, exit code, timing, and cleanup status are returned and saved to the job history.

The agent does not run code on its own. Each run needs a user click, so a person stays in control of what executes.

## Project structure

```
proofbox-ai/
├── backend/
│   ├── app/
│   │   ├── main.py                    # API routes
│   │   ├── db.py                      # SQLite job history
│   │   ├── sandbox/runner.py          # Runs on the sandbox server
│   │   └── services/
│   │       ├── ai_service.py          # Ollama Cloud client
│   │       ├── ai_status.py           # AI provider check
│   │       ├── export_service.py      # JSON and SARIF export
│   │       ├── github_service.py      # Repository scanner
│   │       ├── sandbox_service.py     # Sandbox client (SSH)
│   │       └── verification_service.py
│   ├── requirements.txt
│   └── test_ollama.py                 # Quick check of the AI connection
├── deploy/
│   └── setup_sandbox_vm.sh            # One-time setup for the sandbox server
├── frontend/
│   ├── index.html                     # Dashboard
│   └── app.js                         # Dashboard behaviour
├── tests/
│   ├── test_github_scanner_v2.py
│   └── test_sandbox.py
├── .env.example                       # Copy to .env and fill in
├── .gitignore
└── README.md
```

---

## Setup

### Requirements

- Python 3.12 or newer (developed on 3.13)
- An Ollama Cloud API key, for AI generation
- A Debian or Ubuntu server on Vultr, for the sandbox (optional for the other features)

### 1. Create your environment file

Copy `.env.example` to `.env` and fill in the values:

```env
APP_NAME=ProofBox AI
APP_ENV=development

AI_PROVIDER=ollama
OLLAMA_BASE_URL=https://ollama.com
OLLAMA_MODEL=gpt-oss:120b
OLLAMA_API_KEY=your-key-here

SANDBOX_HOST=your-sandbox-ip
SANDBOX_USER=sandbox
SANDBOX_KEY_PATH=C:/Users/you/.ssh/id_ed25519
```

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

Open **http://127.0.0.1:8000** in your browser. Load the page through the server, not by opening `index.html` directly.

### 3. Set up the sandbox server (optional)

1. Create a small Debian or Ubuntu server on Vultr with your SSH public key.
2. Copy the runner and setup script to the server, then run the setup as root:

   ```bash
   sudo bash setup_sandbox_vm.sh /root/runner.py
   ```

   The script creates the `sandbox` user, installs the runner, blocks the sandbox user's internet access, and checks that the block works. It ends with `Self-test passed`.
3. Add your public key to `/home/sandbox/.ssh/authorized_keys` on the server.
4. Set `SANDBOX_HOST`, `SANDBOX_USER`, and `SANDBOX_KEY_PATH` in `.env`, then restart the server.
5. Open the **Sandbox** page. The status should read **READY**.

---

## Tests

From the project root:

```bash
python tests/test_github_scanner_v2.py
python tests/test_sandbox.py
```

The scanner tests run without network access, using fixtures in place of GitHub. The sandbox tests cover input validation, the SSH protocol, the readiness check, and the runner's safety controls. The runner tests run on Linux with a non-root test user and are skipped on Windows.

---

## Roadmap

1. Connect generation to the sandbox, with a **Run in sandbox** button shown only after the static check passes.
2. Host the web app on Vultr.
3. Add "Fix with AI", which re-scans the patched code before showing the fix.
4. Add diff scanning, dependency checks, and finding suppression with a required reason.
5. Destroy the sandbox server automatically through the Vultr API after each session.

---

## Licence

Coursework project for the Vultr Agent Rush hackathon. Add a licence before accepting outside contributions.