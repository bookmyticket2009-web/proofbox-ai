// ---- Toast notifications (replace blocking showToast()) ----
function showToast(message, tone = "error") {
    let stack = document.getElementById("toastStack");
    if (!stack) {
        stack = document.createElement("div");
        stack.id = "toastStack";
        stack.setAttribute("role", "status");
        stack.setAttribute("aria-live", "polite");
        document.body.appendChild(stack);
    }
    const toast = document.createElement("div");
    toast.className = `toast toast-${tone}`;
    toast.textContent = String(message);
    stack.appendChild(toast);
    requestAnimationFrame(() => toast.classList.add("show"));
    setTimeout(() => {
        toast.classList.remove("show");
        setTimeout(() => toast.remove(), 300);
    }, 4200);
}

// ProofBox AI - Client Application Engine
// Handles View Switching, Live Per-File Streaming Scans,
// SQLite Audit Trails, and Animated Speedometer Cockpit Inspection

document.addEventListener("DOMContentLoaded", () => {
    // Navigation elements
    const workspaceNav = document.getElementById("workspaceNav");
    const githubNav = document.getElementById("githubNav");
    const historyNav = document.getElementById("historyNav");
    const newProjectBtn = document.getElementById("newProject");

    // Views
    const aiWorkspaceView = document.getElementById("aiWorkspaceView");
    const githubScannerView = document.getElementById("githubScannerView");
    const jobHistoryView = document.getElementById("jobHistoryView");

    // Headers & Text
    const topBreadcrumb = document.getElementById("topBreadcrumb");
    const pageTitle = document.getElementById("pageTitle");
    const eyebrowText = document.getElementById("eyebrowText");
    const heroHeading = document.getElementById("heroHeading");
    const heroSubtext = document.getElementById("heroSubtext");

    // Editor elements
    const taskInput = document.getElementById("taskInput");
    const codeEditor = document.getElementById("codeEditor");
    const generateBtn = document.getElementById("generateBtn");
    const verifyBtn = document.getElementById("verifyBtn");
    const copyBtn = document.getElementById("copyBtn");

    // GitHub Scanner elements
    const repoUrlInput = document.getElementById("repoUrlInput");
    const maxFilesInput = document.getElementById("maxFilesInput");
    const scanRepoBtn = document.getElementById("scanRepoBtn");
    const scanTerminalCard = document.getElementById("scanTerminalCard");
    const terminalConsoleStream = document.getElementById("terminalConsoleStream");
    const terminalProgressBar = document.getElementById("terminalProgressBar");
    const terminalStatusText = document.getElementById("terminalStatusText");
    const terminalSpinner = document.getElementById("terminalSpinner");
    const terminalPill = document.getElementById("terminalPill");
    const repoMetaBar = document.getElementById("repoMetaBar");
    const repoFindingsContainer = document.getElementById("repoFindingsContainer");
    const repoFindingsList = document.getElementById("repoFindingsList");
    const stopScanBtn = document.getElementById("stopScanBtn");
    let scanController = null;

    let activeScanId = null;
    let liveFindingCount = 0;
    let exportJobId = null;

    // Builds a finding card. Every value is set with textContent: repository content is
    // untrusted, so it must never be parsed as HTML.
    function buildFindingCard(f) {
        const sev = String(f.severity || "MEDIUM").toUpperCase();
        const card = document.createElement("div");
        card.className = `repo-finding-card severity-${sev}`;

        const top = document.createElement("div");
        top.className = "repo-finding-top";
        const rule = document.createElement("span");
        rule.className = "repo-finding-rule";
        rule.textContent = f.rule_name || f.rule_id || "Security Finding";
        const badge = document.createElement("span");
        badge.className = `severity-badge ${sev}`;
        badge.textContent = sev;
        top.append(rule, badge);
        card.append(top);

        const file = document.createElement("div");
        file.className = "repo-finding-file";
        file.textContent = `File: ${f.file || "unknown"}${f.line_number ? ":" + f.line_number : ""}`;
        card.append(file);

        if (f.line_snippet) {
            const snippet = document.createElement("div");
            snippet.className = "repo-finding-snippet";
            snippet.textContent = f.line_snippet;
            card.append(snippet);
        }
        if (f.remediation) {
            const rem = document.createElement("div");
            rem.className = "repo-finding-remediation";
            const label = document.createElement("strong");
            label.textContent = "Remediation: ";
            rem.append(label, document.createTextNode(f.remediation));
            card.append(rem);
        }
        return card;
    }

    function addLiveFindings(list) {
        if (!repoFindingsList || !Array.isArray(list) || list.length === 0) return;
        if (repoFindingsContainer) repoFindingsContainer.style.display = "block";
        list.forEach(f => {
            const card = buildFindingCard(f);
            card.classList.add("finding-enter");
            repoFindingsList.appendChild(card);
        });
        liveFindingCount += list.length;
        const counter = document.getElementById("repoFindingCount");
        if (counter) counter.textContent = String(liveFindingCount);
        repoFindingsList.scrollTop = repoFindingsList.scrollHeight;
    }

    function resetLiveFindings() {
        liveFindingCount = 0;
        if (repoFindingsList) repoFindingsList.replaceChildren();
        const counter = document.getElementById("repoFindingCount");
        if (counter) counter.textContent = "0";
        if (repoFindingsContainer) repoFindingsContainer.style.display = "block";
        setExportTarget(null);
    }

    function setExportTarget(jobId) {
        exportJobId = jobId || null;
        document.querySelectorAll(".export-btn").forEach(btn => { btn.disabled = !exportJobId; });
    }

    if (stopScanBtn) {
        stopScanBtn.addEventListener("click", async () => {
            if (!scanController) return;
            stopScanBtn.disabled = true;
            stopScanBtn.textContent = "Stopping…";

            // Ask the server to stop. It finishes the current file, then sends partial results
            // over the same stream.
            if (activeScanId) {
                try {
                    const res = await fetch(`${API}/api/github/scan/${encodeURIComponent(activeScanId)}/cancel`, { method: "POST" });
                    if (res.ok) {
                        appendTerminal("Stop requested. Finishing the current file, then returning partial results...", "warn");
                        return;
                    }
                } catch (_) {
                    // Network error: fall back to closing the stream below.
                }
            }
            scanController.abort();
        });
    }

    // Audit History & Cockpit Modal Elements
    const auditTableBody = document.getElementById("auditTableBody");
    const auditCountLabel = document.getElementById("auditCountLabel");
    const refreshAuditBtn = document.getElementById("refreshAuditBtn");
    const clearAuditBtn = document.getElementById("clearAuditBtn");
    const auditModal = document.getElementById("auditModal");
    const closeModalBtn = document.getElementById("closeModalBtn");

    const API = "";

    // -------------------------------------------------------------
    // Screen Switcher (AI Workspace <-> GitHub Scanner <-> Job History)
    // -------------------------------------------------------------
    function hideAllViews() {
        [aiWorkspaceView, githubScannerView, jobHistoryView, document.getElementById("sandboxView")].forEach(v => {
            if (v) v.style.display = "none";
        });
        [workspaceNav, githubNav, historyNav, document.getElementById("sandboxNav")].forEach(n => {
            if (n) n.classList.remove("active");
        });
    }

    function showAIWorkspace() {
        hideAllViews();
        if (workspaceNav) workspaceNav.classList.add("active");
        if (aiWorkspaceView) aiWorkspaceView.style.display = "grid";

        if (topBreadcrumb) topBreadcrumb.innerHTML = "Workspace / <strong>AI Coding</strong>";
        if (pageTitle) pageTitle.textContent = "AI Coding Workspace";
        if (eyebrowText) eyebrowText.textContent = "✦ INTELLIGENT CODE GENERATION";
        if (heroHeading) heroHeading.innerHTML = "Build with AI.<br><span>Verify with confidence.</span>";
        if (heroSubtext) heroSubtext.textContent = "Generate Python snippets, inspect potential risks, and prepare code for isolated execution.";
    }

    function showGitHubScanner() {
        hideAllViews();
        if (githubNav) githubNav.classList.add("active");
        if (githubScannerView) githubScannerView.style.display = "block";

        if (topBreadcrumb) topBreadcrumb.innerHTML = "Security / <strong>GitHub Scanner v2</strong>";
        if (pageTitle) pageTitle.textContent = "GitHub Security Scanner";
        if (eyebrowText) eyebrowText.textContent = "✦ REPOSITORY AUDIT ENGINE";
        if (heroHeading) heroHeading.innerHTML = "Scan Repositories.<br><span>Surface secrets & risks.</span>";
        if (heroSubtext) heroSubtext.textContent = "Audit public GitHub repositories with commit SHA pinning, configurable bounds, and zero code execution.";
    }

    function showJobHistory() {
        hideAllViews();
        if (historyNav) historyNav.classList.add("active");
        if (jobHistoryView) jobHistoryView.style.display = "block";

        if (topBreadcrumb) topBreadcrumb.innerHTML = "Workspace / <strong>Job History</strong>";
        if (pageTitle) pageTitle.textContent = "Job History & Audit Log";
        if (eyebrowText) eyebrowText.textContent = "✦ PERSISTENT COMPLIANCE RECORDS";
        if (heroHeading) heroHeading.innerHTML = "Audit Trail.<br><span>Track every verification.</span>";
        if (heroSubtext) heroSubtext.textContent = "Browse persistent SQLite audit records for code checks, generations, and repository scans.";

        loadAuditHistory();
    }

    // -------------------------------------------------------------
    // Execution environment card (workspace), driven by the live sandbox check
    // -------------------------------------------------------------
    function setExecText(id, text, tone) {
        const el = document.getElementById(id);
        if (!el) return;
        el.textContent = text;
        if (tone) el.className = tone;
    }

    async function refreshExecutionCard() {
        const badge = document.getElementById("execBadge");
        try {
            const res = await fetch(`${API}/api/sandbox/check`, { cache: "no-store" });
            const data = await res.json();
            const checks = data.checks || {};
            const ready = data.ok === true;

            if (badge) {
                badge.textContent = ready ? "READY" : "NOT READY";
                badge.style.color = ready ? "var(--green)" : "var(--red)";
            }
            setExecText("execLocation", data.sandbox_host ? `Remote Linux · ${data.sandbox_host}` : "Remote Linux · not configured", checks.connection ? "green" : "yellow");
            setExecText("execNetwork", checks.network_isolation ? "Blocked" : "Not verified", checks.network_isolation ? "green" : "red");
            setExecText("execCleanup", checks.cleanup ? "Confirmed" : "Not verified", checks.cleanup ? "green" : "red");
            setExecText("execNoticeText", ready
                ? "Code runs in an isolated sandbox: non-root user, no internet access, and strict time, memory, and output limits."
                : (data.label || "The sandbox is not ready."));
        } catch (err) {
            if (badge) {
                badge.textContent = "NOT READY";
                badge.style.color = "var(--red)";
            }
            setExecText("execNoticeText", "Backend unreachable. Start the server to check the sandbox.");
        }
    }

    refreshExecutionCard();
    setInterval(refreshExecutionCard, 120000);

    // -------------------------------------------------------------
    // Remote Sandbox panel
    // -------------------------------------------------------------
    const sandboxNav = document.getElementById("sandboxNav");
    const sandboxView = document.getElementById("sandboxView");
    const sbCode = document.getElementById("sandboxCode");
    const sbTimeout = document.getElementById("sandboxTimeout");
    const sbRun = document.getElementById("sandboxRunBtn");
    const sbConn = document.getElementById("sandboxConnState");
    const sbResult = document.getElementById("sandboxResult");

    function sbText(tag, className, text) {
        const el = document.createElement(tag);
        if (className) el.className = className;
        el.textContent = text;
        return el;
    }

    async function refreshSandboxState() {
        if (!sbConn) return;
        try {
            const res = await fetch(`${API}/api/sandbox/check`, { cache: "no-store" });
            const data = await res.json();
            sbConn.textContent = data.label || (data.ok ? "Ready" : "Not ready");
            sbConn.style.color = data.ok ? "var(--green)" : "var(--red)";
        } catch (err) {
            sbConn.textContent = "Backend unreachable";
            sbConn.style.color = "var(--red)";
        }
    }

    function renderSandboxPending() {
        if (!sbResult) return;
        sbResult.replaceChildren(sbText("div", "sandbox-verdict pending", "RUNNING ON REMOTE SANDBOX..."));
    }

    function renderSandboxResult(data) {
        if (!sbResult) return;
        // "completed" only means the script finished. A nonzero exit code is a failed run.
        const verdictKey = data.status === "completed" && data.exit_code !== 0 ? "failed" : data.status;
        const verdictText = {
            completed: "COMPLETED", error: "ERROR",
            timed_out: "TIMED OUT", output_limit_exceeded: "OUTPUT LIMIT HIT",
        }[verdictKey] || (verdictKey === "failed" ? `FAILED (exit code ${data.exit_code})` : String(verdictKey || "UNKNOWN").toUpperCase());

        const meta = document.createElement("div");
        meta.className = "sandbox-meta";
        const parts = [
            ["Exit code", data.exit_code === null || data.exit_code === undefined ? "—" : String(data.exit_code)],
            ["Duration", data.duration_ms !== undefined ? `${data.duration_ms} ms` : "—"],
            ["Run as uid", data.uid !== undefined ? String(data.uid) : "—"],
            ["Cleanup", data.cleanup_confirmed === true ? "confirmed" : data.cleanup_confirmed === false ? "NOT confirmed" : "—"],
            ["Host", data.sandbox_host || "—"],
        ];
        parts.forEach(([label, value]) => {
            const span = document.createElement("span");
            span.append(`${label}: `);
            const strong = document.createElement("strong");
            strong.textContent = value;
            span.appendChild(strong);
            meta.appendChild(span);
        });

        sbResult.replaceChildren();
        sbResult.appendChild(sbText("div", `sandbox-verdict ${verdictKey || "error"}`, verdictText));
        sbResult.appendChild(meta);

        const addBlock = (title, text, isError) => {
            const block = document.createElement("div");
            block.className = isError ? "sandbox-block err" : "sandbox-block";
            block.appendChild(sbText("h4", "", title));
            const pre = document.createElement("pre");
            pre.textContent = text;
            block.appendChild(pre);
            sbResult.appendChild(block);
        };

        if (data.error) addBlock("ERROR", data.error, true);
        addBlock("STDOUT", data.stdout || "(no output)", false);
        if (data.stderr) addBlock("STDERR", data.stderr, true);
        if (data.stdout_truncated || data.stderr_truncated) {
            sbResult.appendChild(sbText("div", "", "Output was truncated to the sandbox limit."));
        }
        if (data.job_id) {
            sbResult.appendChild(sbText("div", "sandbox-meta", `Saved to job history: ${data.job_id}`));
        }
    }

    function renderSandboxError(message) {
        if (!sbResult) return;
        sbResult.replaceChildren();
        const block = document.createElement("div");
        block.className = "sandbox-block err";
        block.appendChild(sbText("h4", "", "REQUEST FAILED"));
        const pre = document.createElement("pre");
        pre.textContent = message;
        block.appendChild(pre);
        sbResult.appendChild(block);
    }

    function showSandbox() {
        hideAllViews();
        if (sandboxNav) sandboxNav.classList.add("active");
        if (sandboxView) sandboxView.style.display = "block";

        if (topBreadcrumb) topBreadcrumb.innerHTML = "Workspace / <strong>Remote Sandbox</strong>";
        if (pageTitle) pageTitle.textContent = "Remote Sandbox";
        if (eyebrowText) eyebrowText.textContent = "✦ ISOLATED EXECUTION";
        if (heroHeading) heroHeading.innerHTML = "Run Code Safely.<br><span>Contained on a remote server.</span>";
        if (heroSubtext) heroSubtext.textContent = "Code runs on a disposable Linux server as a non-root user, with no internet access and strict limits.";

        refreshSandboxState();
    }

    if (sandboxNav) sandboxNav.addEventListener("click", (e) => { e.preventDefault(); showSandbox(); });

    if (sbRun) {
        sbRun.addEventListener("click", async () => {
            const code = sbCode ? sbCode.value : "";
            if (!code.trim()) {
                showToast("Enter some Python code first.", "warn");
                return;
            }
            const timeout = Math.max(1, Math.min(30, parseInt(sbTimeout ? sbTimeout.value : "10", 10) || 10));

            sbRun.disabled = true;
            sbRun.textContent = "Running...";
            renderSandboxPending();
            try {
                const res = await fetch(`${API}/api/sandbox/run`, {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({ code, timeout }),
                });
                const data = await res.json();
                if (!res.ok) throw new Error(data.detail || `Run failed (HTTP ${res.status})`);
                renderSandboxResult(data);
                logActivity(`Sandbox run ${data.status}.`);
            } catch (err) {
                renderSandboxError(err.message);
                showToast(err.message, "error");
            } finally {
                sbRun.disabled = false;
                sbRun.textContent = "▶ Run in sandbox";
            }
        });
    }

    if (workspaceNav) workspaceNav.addEventListener("click", (e) => { e.preventDefault(); showAIWorkspace(); });
    if (githubNav) githubNav.addEventListener("click", (e) => { e.preventDefault(); showGitHubScanner(); });
    if (historyNav) historyNav.addEventListener("click", (e) => { e.preventDefault(); showJobHistory(); });

    // -------------------------------------------------------------
    // General Utilities
    // -------------------------------------------------------------
    function logActivity(message) {
        const log = document.getElementById("activityLog");
        if (!log) return;
        const item = document.createElement("p");
        const dot = document.createElement("span");
        dot.textContent = "●";
        item.append(dot, document.createTextNode(` ${message}`));
        log.prepend(item);
    }

    function updateLineNumbers() {
        if (!codeEditor) return;
        const lines = codeEditor.value.split("\n").length;
        const lineNums = document.getElementById("lineNumbers");
        const lineCount = document.getElementById("lineCount");
        if (lineNums) lineNums.textContent = Array.from({ length: lines }, (_, i) => i + 1).join("\n");
        if (lineCount) lineCount.textContent = `${lines} lines`;
    }

    function resetSecurityResults() {
        const secScore = document.getElementById("securityScore");
        const secTitle = document.getElementById("securityTitle");
        const secDesc = document.getElementById("securityDescription");
        if (secScore) secScore.textContent = "—";
        if (secTitle) secTitle.textContent = "Awaiting analysis";
        if (secDesc) secDesc.textContent = "Verify your code to see the results.";

        ["syntaxResult", "sizeResult", "riskResult"].forEach(id => {
            const el = document.getElementById(id);
            if (el) { el.textContent = "Pending"; el.style.color = ""; }
        });

        const findingsList = document.getElementById("findingsList");
        if (findingsList) findingsList.textContent = "No analysis has been performed yet.";
    }

    function displayVerification(data) {
        const findings = Array.isArray(data.findings) ? data.findings : [];
        const syntaxPassed = data.syntax_valid !== false;

        const syntaxEl = document.getElementById("syntaxResult");
        const sizeEl = document.getElementById("sizeResult");
        const riskEl = document.getElementById("riskResult");

        if (syntaxEl) {
            syntaxEl.textContent = syntaxPassed ? "Passed" : "Failed";
            syntaxEl.style.color = syntaxPassed ? "var(--green)" : "var(--red)";
        }
        if (sizeEl) {
            sizeEl.textContent = `${codeEditor ? codeEditor.value.length : 0} bytes`;
        }
        if (riskEl) {
            riskEl.textContent = findings.length ? `${findings.length} findings` : "No findings";
            riskEl.style.color = findings.length ? "var(--yellow)" : "var(--green)";
        }

        const secScore = document.getElementById("securityScore");
        const secTitle = document.getElementById("securityTitle");
        if (secScore) secScore.textContent = (syntaxPassed && findings.length === 0) ? "OK" : "!";
        if (secTitle) secTitle.textContent = findings.length === 0 ? "No findings detected" : "Review required";

        const findingsList = document.getElementById("findingsList");
        if (findingsList) {
            findingsList.replaceChildren();
            if (findings.length === 0) {
                findingsList.textContent = syntaxPassed ? "No findings detected by static analysis." : "Code could not be parsed.";
            } else {
                findings.forEach(f => {
                    const item = document.createElement("div");
                    item.className = "finding-item";
                    item.textContent = typeof f === "string" ? f : `${f.rule_name || f.rule_id || 'Risk'}: ${f.description || ''}`;
                    findingsList.appendChild(item);
                });
            }
        }
    }

    // -------------------------------------------------------------
    // Live Terminal Console Helpers
    // -------------------------------------------------------------
    function appendTerminal(msg, type = "info") {
        if (!terminalConsoleStream) return;
        const d = new Date();
        const ts = `[${String(d.getMinutes()).padStart(2, "0")}:${String(d.getSeconds()).padStart(2, "0")}]`;
        const div = document.createElement("div");
        div.className = "console-line";

        const stamp = document.createElement("span");
        stamp.className = "ts";
        stamp.textContent = ts;
        const body = document.createElement("span");
        if (type === "success") {
            body.className = "success-text";
            body.textContent = `✔ ${msg}`;
        } else if (type === "warn") {
            body.className = "warn-text";
            body.textContent = `⚠ ${msg}`;
        } else {
            body.textContent = `➜ ${msg}`;
        }
        div.append(stamp, document.createTextNode(" "), body);
        terminalConsoleStream.appendChild(div);
        terminalConsoleStream.scrollTop = terminalConsoleStream.scrollHeight;
    }

    function setTerminalStep(step, pct, txt) {
        for (let i = 1; i <= 4; i++) {
            const el = document.getElementById(`step${i}`);
            if (el) {
                el.classList.remove("active", "done");
                if (i < step) el.classList.add("done");
                else if (i === step) el.classList.add("active");
            }
        }
        if (terminalProgressBar) terminalProgressBar.style.width = `${pct}%`;
        if (terminalStatusText) terminalStatusText.textContent = txt;
    }

    // -------------------------------------------------------------
    // Click: Generate Code
    // -------------------------------------------------------------
    if (generateBtn) {
        generateBtn.addEventListener("click", async () => {
            const task = taskInput.value.trim();
            if (task.length < 3) {
                showToast("Please describe your task first.");
                return;
            }

            generateBtn.disabled = true;
            generateBtn.textContent = "Generating...";
            resetSecurityResults();
            logActivity(`Submitting task: "${task.substring(0, 30)}..."`);

            try {
                const res = await fetch(`${API}/api/generate-and-verify`, {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({ task })
                });
                const data = await res.json();
                if (!res.ok) throw new Error(data.detail || "Generation failed");

                if (codeEditor) {
                    codeEditor.value = data.code || "";
                    updateLineNumbers();
                }
                displayVerification(data.verification || data);
                logActivity("AI generation and verification completed.");
            } catch (err) {
                logActivity(`Generation failed: ${err.message}`);
                showToast(err.message);
            } finally {
                generateBtn.disabled = false;
                generateBtn.innerHTML = "<span>✦</span> Generate code";
            }
        });
    }

    // -------------------------------------------------------------
    // Click: Verify Code
    // -------------------------------------------------------------
    if (verifyBtn) {
        verifyBtn.addEventListener("click", async () => {
            const code = codeEditor ? codeEditor.value : "";
            if (!code.trim()) {
                showToast("Enter or generate some code first.");
                return;
            }

            verifyBtn.disabled = true;
            verifyBtn.textContent = "Checking...";
            logActivity("Running static code verification...");

            try {
                const res = await fetch(`${API}/api/verify`, {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({ code })
                });
                const data = await res.json();
                if (!res.ok) throw new Error(data.detail || "Verification failed");

                displayVerification(data);
                logActivity("Verification completed.");
            } catch (err) {
                logActivity(`Verification error: ${err.message}`);
                showToast(err.message);
            } finally {
                verifyBtn.disabled = false;
                verifyBtn.textContent = "✓ Verify code";
            }
        });
    }

    // -------------------------------------------------------------
    // Click: Scan GitHub Repository with LIVE PER-FILE UPDATES
    // -------------------------------------------------------------
    if (scanRepoBtn) {
        scanRepoBtn.addEventListener("click", async () => {
            const repoUrl = repoUrlInput ? repoUrlInput.value.trim() : "";
            const maxFiles = maxFilesInput ? parseInt(maxFilesInput.value, 10) : 100;

            if (!repoUrl) {
                showToast("Please enter a valid GitHub repository URL.");
                return;
            }

            if (scanTerminalCard) scanTerminalCard.style.display = "block";
            if (terminalConsoleStream) terminalConsoleStream.replaceChildren();
            resetLiveFindings();
            if (terminalSpinner) terminalSpinner.style.display = "inline-block";
            if (terminalPill) {
                terminalPill.textContent = "SCANNING";
                terminalPill.style.color = "var(--cyan)";
            }

            scanRepoBtn.disabled = true;
            const btnLabel = document.getElementById("scanBtnLabel");
            if (btnLabel) btnLabel.textContent = "Scanning...";

            scanController = new AbortController();
            activeScanId = null;
            if (stopScanBtn) {
                stopScanBtn.hidden = false;
                stopScanBtn.disabled = false;
                stopScanBtn.textContent = "■ Stop scan";
            }

            appendTerminal(`Target: ${repoUrl}`);
            setTerminalStep(1, 10, "Connecting to GitHub gateway...");

            try {
                const response = await fetch(`${API}/api/github/scan/stream`, {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({ repository_url: repoUrl, max_files: maxFiles }),
                    signal: scanController.signal
                });

                if (!response.ok) {
                    throw new Error(`Connection failed with HTTP ${response.status}`);
                }

                const reader = response.body.getReader();
                const decoder = new TextDecoder("utf-8");
                let buffer = "";
                let completedData = null;
                let completedJobId = null;

                while (true) {
                    const { done, value } = await reader.read();
                    if (done) break;

                    buffer += decoder.decode(value, { stream: true });
                    const events = buffer.split("\n\n");
                    buffer = events.pop();

                    for (const eventStr of events) {
                        const trimmed = eventStr.trim();
                        if (!trimmed.startsWith("data: ")) continue;

                        try {
                            const payload = JSON.parse(trimmed.slice(6));
                            const evType = payload.event;

                            if (evType === "started") {
                                activeScanId = payload.scan_id || null;
                            } else if (evType === "status") {
                                setTerminalStep(1, 20, payload.message);
                                appendTerminal(payload.message);
                            } else if (evType === "tree_discovered") {
                                setTerminalStep(2, 35, `Discovered ${payload.discovered} files`);
                                appendTerminal(`Discovered ${payload.discovered} files (queueing ${payload.selected} files to scan).`);
                            } else if (evType === "file_progress") {
                                const pct = Math.min(95, 35 + Math.round((payload.current / payload.total) * 60));
                                setTerminalStep(3, pct, `Scanning file (${payload.current}/${payload.total}): ${payload.file}`);
                                
                                if (payload.status === "scanned") {
                                    addLiveFindings(payload.findings || []);
                                    const findingsText = payload.new_findings > 0 ? ` [${payload.new_findings} risk(s) flagged]` : "";
                                    appendTerminal(`[${payload.current}/${payload.total}] Scanned: ${payload.file}${findingsText}`, payload.new_findings > 0 ? "warn" : "info");
                                } else {
                                    appendTerminal(`[${payload.current}/${payload.total}] Skipped: ${payload.file} (${payload.reason || 'excluded'})`);
                                }
                            } else if (evType === "completed") {
                                completedData = payload.result;
                                completedJobId = payload.job_id || null;
                            } else if (evType === "error") {
                                throw new Error(payload.message || "Scanning error encountered");
                            }
                        } catch (parseErr) {
                            console.error("Stream parse error:", parseErr);
                        }
                    }
                }

                if (!completedData) {
                    throw new Error("Scan stream closed without a final report.");
                }

                // Render Final Results
                const data = completedData;
                setTerminalStep(4, 100, data.cancelled ? "Scan stopped — partial report ready" : "Scan Complete — Report Ready");
                if (terminalSpinner) terminalSpinner.style.display = "none";
                if (terminalPill) {
                    terminalPill.textContent = data.cancelled ? "STOPPED" : data.partial_scan ? "PARTIAL SCAN" : "COMPLETED";
                    terminalPill.style.color = data.cancelled || data.partial_scan ? "var(--yellow)" : "var(--green)";
                }

                appendTerminal(`Pinned SHA: ${data.commit || 'HEAD'}`, "success");
                appendTerminal(`Audit finished: ${data.summary.files_scanned} scanned, ${data.summary.files_skipped} skipped.`, "success");
                appendTerminal(`Total Findings: ${data.summary.total_findings}`, data.summary.total_findings > 0 ? "warn" : "success");

                // Render meta summary cards without text overlapping
                if (repoMetaBar) repoMetaBar.style.display = "grid";
                if (repoFindingsContainer) repoFindingsContainer.style.display = "block";

                const setTxt = (id, txt) => { const el = document.getElementById(id); if (el) { el.textContent = txt; el.title = txt; } };
                const repoClean = (data.repository || repoUrl).replace(/^https?:\/\/github\.com\//, "");
                setTxt("metaRepo", repoClean);
                setTxt("metaSha", (data.commit || "HEAD").substring(0, 10));
                setTxt("metaDiscovered", data.summary.files_discovered ?? 0);
                setTxt("metaScanned", data.summary.files_scanned ?? 0);
                setTxt("metaSkipped", data.summary.files_skipped ?? 0);

                const statusEl = document.getElementById("metaScanStatus");
                if (statusEl) {
                    statusEl.textContent = data.partial_scan ? "Partial Scan" : "Complete";
                    statusEl.className = data.partial_scan ? "yellow" : "green";
                }

                const skipPill = document.getElementById("repoSkipBreakdown");
                if (skipPill) skipPill.textContent = `${data.summary.files_skipped} skipped files`;

                // Render Findings list
                const findings = Array.isArray(data.findings) ? data.findings : [];
                setTxt("repoFindingCount", findings.length);

                if (repoFindingsList) {
                    repoFindingsList.replaceChildren();
                    if (findings.length === 0) {
                        repoFindingsList.innerHTML = '<div class="empty-findings">No security findings or hardcoded secrets detected.</div>';
                    } else {
                        findings.forEach(f => repoFindingsList.appendChild(buildFindingCard(f)));
                    }
                }

                logActivity(`Repository scan finished for ${repoClean}.`);
                setExportTarget(completedJobId);
            } catch (err) {
                if (err.name === "AbortError") {
                    if (terminalSpinner) terminalSpinner.style.display = "none";
                    if (terminalPill) {
                        terminalPill.textContent = "STOPPED";
                        terminalPill.style.color = "var(--yellow)";
                    }
                    appendTerminal("Scan stopped by user.", "warn");
                    logActivity("Repository scan stopped by user.");
                    return;
                }
                if (terminalSpinner) terminalSpinner.style.display = "none";
                if (terminalPill) {
                    terminalPill.textContent = "FAILED";
                    terminalPill.style.color = "var(--red)";
                }
                appendTerminal(`Error: ${err.message}`, "warn");
                showToast(err.message);
            } finally {
                scanRepoBtn.disabled = false;
                if (btnLabel) btnLabel.textContent = "Scan repository";
                scanController = null;
                if (stopScanBtn) stopScanBtn.hidden = true;
            }
        });
    }

    // ---- Report export (JSON / SARIF) ----
    document.querySelectorAll(".export-btn").forEach(btn => {
        btn.addEventListener("click", async () => {
            if (!exportJobId) return;
            const format = btn.dataset.format === "sarif" ? "sarif" : "json";
            const jobId = exportJobId;
            btn.disabled = true;
            try {
                const res = await fetch(`${API}/api/jobs/${encodeURIComponent(jobId)}/export?format=${format}`);
                if (!res.ok) throw new Error(`Export failed (HTTP ${res.status})`);
                const blob = await res.blob();
                const url = URL.createObjectURL(blob);
                const link = document.createElement("a");
                link.href = url;
                link.download = `proofbox-${jobId.slice(0, 8)}.${format === "sarif" ? "sarif.json" : "json"}`;
                document.body.appendChild(link);
                link.click();
                link.remove();
                setTimeout(() => URL.revokeObjectURL(url), 1000);
                showToast(`${format.toUpperCase()} report downloaded.`, "success");
            } catch (err) {
                showToast(err.message, "error");
            } finally {
                btn.disabled = !exportJobId;
            }
        });
    });

    // -------------------------------------------------------------
    // Audit History Operations
    // -------------------------------------------------------------
    async function loadAuditHistory() {
        if (!auditTableBody) return;
        auditTableBody.innerHTML = `<tr><td colspan="7" style="text-align: center; color: var(--muted); padding: 20px;">Fetching audit history...</td></tr>`;

        try {
            const res = await fetch(`${API}/api/jobs?limit=50`);
            const data = await res.json();
            const jobs = data.jobs || [];

            if (auditCountLabel) auditCountLabel.textContent = `${jobs.length} audit records`;

            if (jobs.length === 0) {
                auditTableBody.innerHTML = `<tr><td colspan="7" style="text-align: center; color: var(--muted); padding: 20px;">No audit records found. Run a verification or scan to populate history.</td></tr>`;
                return;
            }

            auditTableBody.replaceChildren();

            jobs.forEach(job => {
                const tr = document.createElement("tr");
                const dt = new Date(job.created_at);
                const timeStr = `${dt.toLocaleDateString()} ${dt.toLocaleTimeString()}`;
                const shaShort = job.commit_sha ? job.commit_sha.substring(0, 8) : "—";

                tr.innerHTML = `
                    <td class="cell-time"></td>
                    <td><span class="audit-type-badge"></span></td>
                    <td class="cell-target" style="max-width: 180px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;"></td>
                    <td><code class="cell-sha"></code></td>
                    <td><strong class="cell-findings"></strong></td>
                    <td><span class="cell-status"></span></td>
                    <td><button class="view-detail-btn" type="button">Inspect</button></td>
                `;
                const jobTypeClass = String(job.job_type || "").replace(/[^A-Za-z0-9_-]/g, "");
                const badge = tr.querySelector(".audit-type-badge");
                badge.classList.add(`type-${jobTypeClass}`);
                badge.textContent = job.job_type || "";
                tr.querySelector(".cell-time").textContent = timeStr;
                const targetCell = tr.querySelector(".cell-target");
                targetCell.textContent = job.target || "";
                targetCell.title = job.target || "";
                tr.querySelector(".cell-sha").textContent = shaShort;
                const findingCell = tr.querySelector(".cell-findings");
                findingCell.textContent = String(job.total_findings ?? 0);
                findingCell.className = job.total_findings > 0 ? "yellow" : "green";
                const statusCell = tr.querySelector(".cell-status");
                statusCell.textContent = job.status || "";
                statusCell.className = job.status === "completed" || job.status === "passed" ? "green" : job.status === "partial" ? "yellow" : "red";
                tr.querySelector(".view-detail-btn").dataset.id = job.id;

                tr.querySelector(".view-detail-btn").addEventListener("click", () => inspectJobDetail(job.id));
                auditTableBody.appendChild(tr);
            });
        } catch (err) {
            auditTableBody.replaceChildren();
            const errRow = document.createElement("tr");
            const errCell = document.createElement("td");
            errCell.colSpan = 7;
            errCell.style.cssText = "text-align: center; color: var(--red); padding: 20px;";
            errCell.textContent = `Failed to load audit history: ${err.message}`;
            errRow.appendChild(errCell);
            auditTableBody.appendChild(errRow);
        }
    }

    // -------------------------------------------------------------
    // Automotive Speedometer Rev-Up Sweep Animation
    // -------------------------------------------------------------
    let speedometerAnimFrame = null;

    function animateSpeedometer(targetScore) {
        if (speedometerAnimFrame) cancelAnimationFrame(speedometerAnimFrame);

        const needleGroup = document.getElementById("needleGroup");
        const scoreVal = document.getElementById("gaugeScoreValue");
        const ratingText = document.getElementById("gaugeRatingText");
        const fillPath = document.getElementById("gaugeFillPath");

        const target = Math.max(0, Math.min(100, Math.round(targetScore)));
        const TOTAL_ARC = 267;
        
        const startTime = performance.now();
        const duration = 1200; // 1.2s smooth automotive rev-up sweep

        function frame(now) {
            const elapsed = now - startTime;
            const progress = Math.min(1, elapsed / duration);
            
            // Cubic ease-out curve (mimics mechanical needle inertia)
            const easeOut = 1 - Math.pow(1 - progress, 3);
            const currentScore = target * easeOut;

            // Needle Angle: -90deg is 0 (Red left), +90deg is 100 (Green right)
            const angle = -90 + (currentScore / 100) * 180;
            if (needleGroup) {
                needleGroup.style.transform = `rotate(${angle}deg)`;
            }

            // Fill stroke dashoffset: 267 is empty, 0 is full
            const offset = TOTAL_ARC - (currentScore / 100) * TOTAL_ARC;
            if (fillPath) {
                fillPath.style.strokeDashoffset = offset;
            }

            // Digital counter update
            if (scoreVal) {
                scoreVal.textContent = Math.round(currentScore);
            }

            if (progress < 1) {
                speedometerAnimFrame = requestAnimationFrame(frame);
            } else {
                if (ratingText) {
                    if (target >= 90) {
                        ratingText.textContent = "SAFE & HEALTHY";
                        ratingText.style.color = "var(--green)";
                    } else if (target >= 60) {
                        ratingText.textContent = "MODERATE RISK";
                        ratingText.style.color = "var(--yellow)";
                    } else {
                        ratingText.textContent = "HIGH EXPOSURE";
                        ratingText.style.color = "var(--red)";
                    }
                }
            }
        }

        speedometerAnimFrame = requestAnimationFrame(frame);
    }

    // -------------------------------------------------------------
    // Cockpit Inspector with Real Code Snapshot & Animated Speedometer
    // -------------------------------------------------------------
    // Cockpit view for sandbox runs. Code runs are not security scans, so this shows
    // the code, the output, and the run details instead of a "zero vulnerabilities" verdict.
    function renderSandboxRunInspect(job) {
        const summary = job.summary || {};
        const statusMap = {
            completed: ["EXECUTED", "var(--green)", "rgba(57, 217, 138, 0.15)", "rgba(57, 217, 138, 0.3)"],
            failed: ["RUN FAILED", "var(--red)", "rgba(255, 102, 122, 0.15)", "rgba(255, 102, 122, 0.3)"],
            timed_out: ["TIMED OUT", "var(--yellow)", "rgba(245, 189, 79, 0.15)", "rgba(245, 189, 79, 0.3)"],
            output_limit_exceeded: ["OUTPUT LIMIT", "var(--yellow)", "rgba(245, 189, 79, 0.15)", "rgba(245, 189, 79, 0.3)"],
        };
        const [label, color, bg, border] = statusMap[job.status] || [String(job.status || "UNKNOWN").toUpperCase(), "var(--muted)", "rgba(135,149,170,0.15)", "rgba(135,149,170,0.3)"];

        document.getElementById("cockpitTypeTag").textContent = "SANDBOX RUN";
        document.getElementById("cockpitTitle").textContent = job.target || "Sandbox run";
        const targetSub = document.getElementById("cockpitTargetSub");
        targetSub.replaceChildren();
        targetSub.append("Host: ", sbText("strong", "", summary.sandbox_host || "unknown"));

        const badge = document.getElementById("cockpitStatusBadge");
        badge.textContent = label;
        badge.style.color = color;
        badge.style.background = bg;
        badge.style.borderColor = border;

        // A run is not a security score, so the gauge and counters are not used for it.
        document.getElementById("gaugeScoreValue").textContent = "—";
        document.getElementById("needleGroup").style.transform = "rotate(-90deg)";
        document.getElementById("gaugeFillPath").style.strokeDashoffset = "267";
        document.getElementById("cockpitFindingsCount").textContent = "N/A";
        document.getElementById("cockpitFindingsCount").className = "";
        document.getElementById("cockpitMaxSev").textContent = "N/A";
        document.getElementById("cockpitMaxSev").className = "";

        const dt = new Date(job.created_at);
        document.getElementById("cockpitTimestamp").textContent = `${dt.getMonth()+1}/${dt.getDate()} ${dt.toLocaleTimeString()}`;

        // Left column: the code that was run
        const code = job.code_content || "# No code was saved for this run.";
        const codeViewer = document.getElementById("cockpitCodeViewer");
        const lineNums = document.getElementById("cockpitLineNumbers");
        codeViewer.textContent = code;
        if (window.Prism) {
            codeViewer.className = "language-python";
            Prism.highlightElement(codeViewer);
        }
        const lines = code.split("\n").length;
        if (lineNums) lineNums.textContent = Array.from({ length: lines }, (_, i) => i + 1).join("\n");
        document.getElementById("cockpitCodeLines").textContent = `${lines} lines`;
        document.getElementById("cockpitFileTab").textContent = "◈ main.py";

        // Right column: the run details and output
        const list = document.getElementById("cockpitFindingsList");
        list.replaceChildren();
        const facts = [
            ["Status", job.status || "unknown"],
            ["Exit code", summary.exit_code === null || summary.exit_code === undefined ? "—" : String(summary.exit_code)],
            ["Duration", summary.duration_ms !== undefined ? `${summary.duration_ms} ms` : "—"],
            ["Ran as uid", summary.uid !== undefined ? String(summary.uid) : "—"],
            ["Timed out", summary.timed_out ? "yes" : "no"],
            ["Cleanup", summary.cleanup_confirmed === true ? "confirmed" : summary.cleanup_confirmed === false ? "NOT confirmed" : "—"],
        ];
        const factBox = document.createElement("div");
        factBox.className = "sandbox-meta";
        facts.forEach(([k, v]) => {
            const span = document.createElement("span");
            span.append(`${k}: `);
            span.appendChild(sbText("strong", "", v));
            factBox.appendChild(span);
        });
        list.appendChild(factBox);

        const addBlock = (title, text, isError) => {
            const block = document.createElement("div");
            block.className = isError ? "sandbox-block err" : "sandbox-block";
            block.style.marginTop = "12px";
            block.appendChild(sbText("h4", "", title));
            const pre = document.createElement("pre");
            pre.textContent = text;
            block.appendChild(pre);
            list.appendChild(block);
        };
        if (summary.error) addBlock("ERROR", summary.error, true);
        addBlock("STDOUT", summary.stdout || "(no output)", false);
        if (summary.stderr) addBlock("STDERR", summary.stderr, true);
    }

    async function inspectJobDetail(jobId) {
        if (!auditModal) return;
        auditModal.style.display = "grid";

        // Initial loading indicators
        document.getElementById("cockpitTitle").textContent = "Loading audit cockpit...";
        document.getElementById("cockpitCodeViewer").textContent = "# Retrieving saved snapshot...";
        document.getElementById("cockpitFindingsList").innerHTML = '<div style="color: var(--muted); font-size: 11px;">Retrieving findings...</div>';
        
        // Reset speedometer to 0 before starting sweep
        document.getElementById("gaugeScoreValue").textContent = "0";
        document.getElementById("needleGroup").style.transform = "rotate(-90deg)";
        document.getElementById("gaugeFillPath").style.strokeDashoffset = "267";

        try {
            const res = await fetch(`${API}/api/jobs/${jobId}`);
            const job = await res.json();
            const findings = job.findings || [];

            if (job.job_type === "sandbox_run") {
                renderSandboxRunInspect(job);
                return;
            }

            // Title & Subtitle fix (Dynamic target & commit)
            document.getElementById("cockpitTypeTag").textContent = `${job.job_type.replace(/_/g, ' ')} COCKPIT`;
            document.getElementById("cockpitTitle").textContent = job.target || "Job Inspection";
            
            const targetSub = document.getElementById("cockpitTargetSub");
            const shaCode = job.commit_sha ? job.commit_sha.substring(0, 10) : "HEAD";
            targetSub.replaceChildren();
            const targetLabel = document.createElement("strong");
            targetLabel.textContent = job.target || "";
            const refCode = document.createElement("code");
            refCode.textContent = shaCode;
            targetSub.append("Target: ", targetLabel, " · Ref: ", refCode);

            // Status Badge Fix: Check for both 'completed' and 'passed'
            const badge = document.getElementById("cockpitStatusBadge");
            const isClean = findings.length === 0 && ["completed", "passed"].includes(job.status);
            
            if (isClean) {
                badge.textContent = "PASSED / CLEAN";
                badge.style.color = "var(--green)";
                badge.style.background = "rgba(57, 217, 138, 0.15)";
                badge.style.borderColor = "rgba(57, 217, 138, 0.3)";
            } else if (job.status === "partial") {
                badge.textContent = "PARTIAL SCAN";
                badge.style.color = "var(--yellow)";
                badge.style.background = "rgba(245, 189, 79, 0.15)";
                badge.style.borderColor = "rgba(245, 189, 79, 0.3)";
            } else {
                badge.textContent = "RISK DETECTED";
                badge.style.color = "var(--red)";
                badge.style.background = "rgba(255, 102, 122, 0.15)";
                badge.style.borderColor = "rgba(255, 102, 122, 0.3)";
            }

            // Calculate Safety Score (100 down to 0)
            let penalty = 0;
            let peakSeverity = "NONE";

            findings.forEach(f => {
                const s = (f.severity || "medium").toLowerCase();
                if (s === "critical") { penalty += 35; peakSeverity = "CRITICAL"; }
                else if (s === "high") { penalty += 20; if (peakSeverity !== "CRITICAL") peakSeverity = "HIGH"; }
                else if (s === "medium") { penalty += 10; if (!["CRITICAL", "HIGH"].includes(peakSeverity)) peakSeverity = "MEDIUM"; }
                else { penalty += 5; }
            });

            const finalScore = Math.max(0, 100 - penalty);
            
            // Trigger the speedometer rev-up animation
            animateSpeedometer(finalScore);

            // Stat Cards
            const findCountEl = document.getElementById("cockpitFindingsCount");
            findCountEl.textContent = findings.length;
            findCountEl.className = findings.length === 0 ? "green" : "red";

            const peakEl = document.getElementById("cockpitMaxSev");
            peakEl.textContent = peakSeverity;
            peakEl.className = peakSeverity === "NONE" ? "green" : (peakSeverity === "CRITICAL" ? "red" : "yellow");

            const dt = new Date(job.created_at);
            document.getElementById("cockpitTimestamp").textContent = `${dt.getMonth()+1}/${dt.getDate()} ${dt.toLocaleTimeString()}`;

            // ---------------------------------------------------------
            // LEFT COLUMN: RENDER SOURCE CODE
            // ---------------------------------------------------------
            const codeViewer = document.getElementById("cockpitCodeViewer");
            const lineNums = document.getElementById("cockpitLineNumbers");
            const fileTab = document.getElementById("cockpitFileTab");

            let displayCode = "";
            
            // 1. Direct code stored in code_content or summary.code
            if (job.code_content) {
                displayCode = job.code_content;
            } else if (job.summary && job.summary.code) {
                displayCode = job.summary.code;
            } else if (job.summary && job.summary.prompt && job.job_type === "code_generation") {
                displayCode = `# Task Description:\n# ${job.summary.prompt}\n\n# Code generated under this job ID.`;
            } else if (findings.length > 0 && findings[0].line_snippet) {
                // 2. For repository scans with findings: render code excerpts with line numbers
                displayCode = findings.map(f => 
                    `# File: ${f.file || 'unknown'} (Line ${f.line_number || 1})\n` +
                    `# Threat: ${f.rule_name || 'Flagged Vulnerability'} [${(f.severity || 'HIGH').toUpperCase()}]\n` +
                    `${f.line_snippet || ''}\n` +
                    `# Remediation: ${f.remediation || 'Inspect and refactor.'}\n`
                ).join("\n------------------------------------------------------------\n\n");
            } else if (job.summary && Array.isArray(job.summary.scanned_files) && job.summary.scanned_files.length > 0) {
                // 3. For clean repository scans: list all successfully verified repository files
                displayCode = `# Repository Audit Log: ${job.target}\n# Ref: ${shaCode}\n# All ${job.summary.scanned_files.length} scanned files verified safe against active heuristics:\n\n` +
                    job.summary.scanned_files.map((file, i) => `${String(i + 1).padStart(3, ' ')}. [VERIFIED SAFE]  ${file}`).join("\n");
            } else {
                displayCode = `# Clean audit record for: ${job.target}\n# Commit: ${shaCode}\n# Verified clean at ${job.created_at}\n\n# Zero vulnerabilities, secrets, or dangerous execution patterns detected.`;
            }

            codeViewer.textContent = displayCode;
            if (window.Prism) {
                codeViewer.className = "language-python";
                Prism.highlightElement(codeViewer);
            }
            const lines = displayCode.split("\n").length;
            lineNums.textContent = Array.from({ length: lines }, (_, i) => i + 1).join("\n");
            document.getElementById("cockpitCodeLines").textContent = `${lines} lines`;

            const cleanFileName = job.target.split('/').pop() || (job.job_type === 'github_scan' ? 'repo_scan.log' : 'main.py');
            fileTab.textContent = `◈ ${cleanFileName}`;

            // ---------------------------------------------------------
            // RIGHT COLUMN: RENDER FINDINGS CARDS
            // ---------------------------------------------------------
            const findingsList = document.getElementById("cockpitFindingsList");
            findingsList.replaceChildren();

            if (findings.length === 0) {
                findingsList.innerHTML = `
                    <div style="background: rgba(57, 217, 138, 0.08); border: 1px solid rgba(57, 217, 138, 0.25); border-radius: 6px; padding: 14px; color: #a3e6cb; font-size: 11px;">
                        ✔ Zero vulnerabilities or exposed tokens detected. The code satisfies static rules.
                    </div>
                `;
            } else {
                findings.forEach(f => findingsList.appendChild(buildFindingCard(f)));
            }

        } catch (err) {
            document.getElementById("cockpitTitle").textContent = "Failed to load cockpit";
            document.getElementById("cockpitCodeViewer").textContent = `Error: ${err.message}`;
        }
    }

    if (closeModalBtn) closeModalBtn.addEventListener("click", () => { auditModal.style.display = "none"; });
    if (auditModal) auditModal.addEventListener("click", (e) => { if (e.target === auditModal) auditModal.style.display = "none"; });

    if (refreshAuditBtn) refreshAuditBtn.addEventListener("click", loadAuditHistory);

    if (clearAuditBtn) {
        clearAuditBtn.addEventListener("click", async () => {
            if (!confirm("Are you sure you want to clear all persistent audit records?")) return;
            try {
                await fetch(`${API}/api/jobs`, { method: "DELETE" });
                loadAuditHistory();
            } catch (err) {
                showToast(`Failed to clear: ${err.message}`);
            }
        });
    }

    // -------------------------------------------------------------
    // General Actions
    // -------------------------------------------------------------
    // Copies text on any origin. The modern clipboard API needs HTTPS or localhost,
    // so over plain HTTP we fall back to a hidden textarea and execCommand("copy").
    async function copyText(text) {
        if (navigator.clipboard && window.isSecureContext) {
            try {
                await navigator.clipboard.writeText(text);
                return true;
            } catch (err) {
                // fall through to the fallback below
            }
        }
        const area = document.createElement("textarea");
        area.value = text;
        area.setAttribute("readonly", "");
        area.style.position = "fixed";
        area.style.top = "-1000px";
        document.body.appendChild(area);
        area.select();
        let ok = false;
        try {
            ok = document.execCommand("copy");
        } catch (err) {
            ok = false;
        }
        document.body.removeChild(area);
        return ok;
    }

    if (copyBtn) {
        copyBtn.addEventListener("click", async () => {
            if (!codeEditor || !codeEditor.value) { showToast("No code to copy."); return; }
            const copied = await copyText(codeEditor.value);
            if (!copied) { showToast("Copy failed. Select the code and press Ctrl+C.", "warn"); return; }
            copyBtn.textContent = "Copied!";
            setTimeout(() => { copyBtn.textContent = "Copy code"; }, 1500);
        });
    }

    if (newProjectBtn) {
        newProjectBtn.addEventListener("click", () => {
            if (taskInput) taskInput.value = "";
            if (codeEditor) codeEditor.value = "";
            updateLineNumbers();
            resetSecurityResults();
            showAIWorkspace();
            logActivity("New coding task started.");
        });
    }

    if (codeEditor) codeEditor.addEventListener("input", updateLineNumbers);

    // Initial load
    showAIWorkspace();
    updateLineNumbers();
});
// ---- Live backend health + AI provider status (sidebar) ----
(function initHealthIndicator() {
    const backendEl = document.getElementById("backendStatus");
    const aiEl = document.getElementById("aiStatus");
    const footerDot = document.querySelector(".sidebar-footer .status-dot");

    const AI_STATES = {
        connected: ["Connected", "green"],
        no_key: ["No API key", "red"],
        invalid_key: ["Key rejected", "red"],
        unreachable: ["Unreachable", "red"],
        unsupported: ["Unsupported", "yellow"],
        error: ["Provider error", "yellow"],
    };

    function setStatus(el, text, tone) {
        if (!el) return;
        el.textContent = text;
        el.className = tone;
    }

    function setDot(state) {
        if (footerDot) footerDot.dataset.state = state;
    }

    async function checkAIStatus() {
        try {
            const res = await fetch("/api/ai/status", { cache: "no-store" });
            if (!res.ok) throw new Error("HTTP " + res.status);
            const data = await res.json();
            const [text, tone] = AI_STATES[data.state] || ["Unknown", "yellow"];
            setStatus(aiEl, text, tone);
            if (aiEl) aiEl.title = data.label || "";
        } catch (err) {
            setStatus(aiEl, "Unavailable", "red");
        }
    }

    async function checkHealth() {
        try {
            const res = await fetch("/api/health", { cache: "no-store" });
            if (!res.ok) throw new Error("HTTP " + res.status);
            setStatus(backendEl, "Online", "green");
            setDot("online");
            checkAIStatus();
        } catch (err) {
            setStatus(backendEl, "Offline", "red");
            setDot("offline");
            setStatus(aiEl, "Unavailable", "red");
        }
    }

    document.addEventListener("DOMContentLoaded", checkHealth);
    setInterval(checkHealth, 30000);
})();

// ---- Keyboard shortcuts ----
// Ctrl/Cmd+Enter: run the active view's primary action
// Esc: stop a running scan, otherwise close the cockpit
document.addEventListener("keydown", (e) => {
    const modal = document.getElementById("auditModal");
    const stopBtn = document.getElementById("stopScanBtn");
    const scanBtn = document.getElementById("scanRepoBtn");
    const verifyBtn = document.getElementById("verifyBtn");
    const inScanner = document.getElementById("githubScannerView")?.classList.contains("active-view");

    if (e.key === "Escape") {
        if (modal && modal.style.display === "grid") {
            modal.style.display = "none";
        } else if (stopBtn && !stopBtn.hidden && !stopBtn.disabled) {
            stopBtn.click();
        }
        return;
    }

    if ((e.ctrlKey || e.metaKey) && e.key === "Enter") {
        e.preventDefault();
        const target = inScanner ? scanBtn : verifyBtn;
        if (target && !target.disabled) target.click();
    }
});
