# BRDS-PEC

## Behavioral Ransomware Detection System with Pre-Encryption Containment

> An AI-powered behavioral ransomware detection system that identifies malicious activity **before file encryption begins** using deep sequence modeling on Windows Sysmon telemetry.

---

## Overview

Traditional antivirus solutions rely on malware signatures or detect ransomware only after encryption has started. BRDS-PEC takes a different approach by monitoring **behavioral patterns** from Windows Sysmon telemetry and using a **multi-stage machine learning pipeline** to detect ransomware during its early execution phase.

The system features a **guarded automated containment engine** designed with multi-gate safety checks. In standard operation, containment runs in safe dry-run mode. Once a high-confidence attack is identified ($\ge 0.85$), it:

- Creates HMAC-SHA256 signed alerts with cryptographic integrity verification
- Logs intended host-isolation and process-tree termination actions (dry-run default) or executes guarded containment in approved lab VMs
- Generates explainable AI (SHAP / PyTorch Autograd) attribution reports with explicit provenance tracking and signed contribution directions ($+/-$)
- Stores the incident in a SQLite database for forensic analysis via the SOC dashboard

> **Validation Status:** Guarded live containment capability is implemented with strict multi-gate safety checks, but remains pending end-to-end isolated-VM validation. Default operation is strictly dry-run.

---

## Evaluation Results

Trained on **20,402 behavioral windows** (2,785 ransomware attack + 17,617 genuine Windows 11 benign windows from the [SILRAD-1.0 dataset](https://github.com/JamilIsp/SILRAD-dataset)) with strict source-level splits preventing scenario leakage:

### Benchmark Evaluation (Held-Out Test Set: 5,258 Windows)
| Model / Pipeline Configuration | Decision Gate / Threshold | Precision | Recall | F1 Score | ROC-AUC | FPR | Notes |
|:---|:---:|:---:|:---:|:---:|:---:|:---:|:---|
| **Tier-1 Fast Path (Logistic Regression)** | $\\tau = 0.50$ | 99.54% | 99.48% | **99.51%** | 0.9987 | 0.23% | Linear baseline model (aseline_report.json) |
| **Tier-2 Deep Path (Standalone BiLSTM)** | $\\tau = 0.85$ | 100.0% | 99.94% | **99.97%** | 0.9999 | 0.00% | Evaluated on all 5,258 windows without screening |
| **Two-Stage Pipeline (Continuous Gate)** | $\\text{IF} \\ge -0.167$, $\\tau = 0.85$ | 100.0% | 99.83% | **99.91%** | 0.9992 | 0.00% | 48.27% BiLSTM workload reduction; 99.88% IF screening recall |
| **Two-Stage Pipeline (Legacy Binary Gate)** | $\\text{predict}() == -1$, $\\tau = 0.85$ | 100.0% | 0.40% | **0.80%** | 0.4790 | 0.00% | Historic default gate in 	wo_stage_evaluation_report.json |

### Independent Cross-Source & Generalization Validation
To ensure real-world robustness beyond homogeneous benchmark splits, the architecture was subjected to independent cross-source evaluation:
- **Cross-Source Two-Stage ROC-AUC:** `0.8749` on balanced external evaluation sets.
- **Cross-Source PR-AUC (Average Precision):** `0.8641`.
- **Stage-1 (Isolation Forest) Screening Recall:** `89.21%` of attack windows forwarded to Tier 2.
- **Inference Workload Reduction:** `41.94%` of normal windows screened out on the fast path.
- **Leave-One-Scenario-Out (LOSO) Mean F1:** `93.14%` (Tier-1 Logistic Regression baseline, 4 held-out attack families: Atomic Red Team 94.86%, DCrypt 78.26%, Ransomware Notes 99.74%, SamSam 99.71%).

> **SILRAD Threshold Note:** Cross-source ROC-AUC `0.8749` and PR-AUC `0.8641` reflect ranking capability only. At the fixed production threshold (τ = 0.85), binary precision/recall/F1 are all `0.00%` — SILRAD attack windows produce raw BiLSTM sigmoid outputs in the range 5.8×10⁻⁵ to 1.0×10⁻⁴ due to domain shift (registry-event dominance vs. the file-deletion bursts used during training). Threshold calibration is required for cross-environment binary alerting.

> **Note:** Detection lead time requires verified per-scenario key-exchange or file-rename start markers; see evaluation audit reports for detailed timing breakdowns.

---

## Key Features

- **Behavioral Detection** — monitors Sysmon event sequences across 17 behavioral features, not static file hashes
- **Two-Stage ML Pipeline** — Isolation Forest anomaly screening (candidate threshold `-0.188196`) $\to$ BiLSTM sequence classification
- **Real Baseline Data** — 17,617 genuine Windows 11 benign windows from SILRAD-1.0
- **Cryptographic Alert Integrity** — HMAC-SHA256 signed alert containers (`verify_and_load`) and expiring, single-use, nonce-bearing arm tokens with atomic replay prevention
- **Fail-Closed API Security** — constant-time API key verification (`BRDS_API_KEY`) rejects unauthenticated ingestion and status requests
- **Explainable AI (XAI)** — PyTorch Autograd gradient attributions explain every alert with explicit provenance tracking (`model_derived: true`) and preserved positive/negative impact directions
- **SOC Dashboard** — dark-mode real-time monitoring with Chart.js risk timeline and PDF forensic export
- **Multi-Gate Containment** — host isolation with pre-containment network adapter state tracking, state-aware rollback, and process tree collapse (dry-run default, guarded lab execution)
- **108 Automated Tests** — 100% passing test suite covering backend auth, ML pipeline, containment gates, HMAC verification, XAI provenance, and SILRAD adapter

---

## System Architecture

```
Windows Sysmon (v15+) Event Logging (Event IDs 1, 3, 7, 11, 12, 13, 23, 26)
  ↓
Pipeline Parse & Temporal Aggregation (5-second Sliding Windows, 17 Features)
  ↓
Isolation Forest (Tier 1 — Continuous Anomaly Screening)
  ↓ (score >= BRDS_IF_SCREENING_THRESHOLD)
Deep LSTM Sequence Classifier (Tier 2 — 2-layer Bidirectional LSTM, 30 Timesteps)
  ↓
Risk Score ∈ [0.0, 1.0]
  ↓
≥ 0.85 → HMAC-SHA256 Signed Alert Container → Multi-Gate Containment (Dry-run default)
  ↓
SOC Dashboard & XAI Attribution Modal (Model-derived vs fallback provenance)
```

---

## Detection & Safety Pipeline

### Phase 1 — Telemetry Collection

Sysmon events are parsed from `.evtx` or `.log` files and filtered to security-relevant IDs:

| Event ID | Description |
|:---|:---|
| 1 | Process Creation |
| 3 | Network Connection |
| 7 | DLL / Image Loaded |
| 11 | File Creation |
| 12 | Registry Object Created |
| 13 | Registry Value Modified |
| 23 | File Delete (archived) |
| 26 | File Delete (logged) |

### Phase 2 — Feature Engineering

Events are aggregated into 5-second sliding windows per process, producing 17 numeric behavioral features: event counts by type, unique images/files/extensions, network destinations, suspicious path indicators, and composite activity scores.

### Phase 3 — AI Detection Engine

**Tier 1 — Isolation Forest:** Screens out normal system activity with continuous anomaly scoring (`BRDS_IF_SCREENING_THRESHOLD`).

**Tier 2 — LSTM Classifier:** A 2-layer Bidirectional LSTM with hidden dimension 64, concatenated Mean + Max pooling across 30 timesteps, and sigmoid output. Loaded with `torch.load(..., weights_only=True)` and verified against a SHA-256 hash manifest.

### Phase 4 — Multi-Gate Containment & Rollback

When risk $\ge 0.85$, the containment engine evaluates the multi-gate authorization:

$$\text{BRDS\_LAB\_ENVIRONMENT\_APPROVED=1} \land \text{BRDS\_LIVE\_CONTAINMENT=1} \land \text{Valid HMAC .arm\_token} \implies \text{Armed Execution}$$

- **Dry-Run Mode (Default):** Passes `-DryRunOverride` to PowerShell containment scripts. Logs planned actions to `data/processed/containment_audit.jsonl` without host disruption.
- **Lab Armed Mode (Isolated Sandbox VM Only):**
  - Process tree termination (`kill_process_tree.ps1 -Armed`): Collapses the malicious PID process tree while protecting critical Windows system processes (`lsass`, `csrss`, `explorer`, `svchost`, etc.).
  - Network isolation (`ContainHost.ps1 -Armed`): Disables active network adapters via `Disable-NetAdapter`.
  - Authenticated Status Sync: Notifies backend via `POST /api/containment/status` (`X-BRDS-API-Key`).
- **Network Rollback:** [`containment/RollbackHost.ps1`](containment/RollbackHost.ps1) is available to restore network adapters after detonation testing.

---

## Technology Stack

| Category | Technologies |
|:---|:---|
| **Core Runtime** | Python 3.14, PowerShell 5.1/7+ |
| **Deep Learning** | PyTorch ≥ 2.0.0 (LSTM Classifier) |
| **Machine Learning** | Scikit-Learn (Isolation Forest, Logistic Regression) |
| **Explainable AI** | SHAP, PyTorch Autograd Gradients, ReportLab PDF Engine |
| **Data Processing** | Pandas, NumPy, python-evtx |
| **Backend** | Flask, Flask-SQLAlchemy, Flask-CORS |
| **Database** | SQLite (`brds.db`) |
| **Frontend** | HTML5, CSS3, JavaScript (ES6), Chart.js |
| **Security** | HMAC-SHA256, SHA-256 model integrity, constant-time auth (`hmac.compare_digest`) |
| **Testing** | PyTest (108 automated tests, 100% passing) |

---

## Datasets & Methodology

The ML pipeline is trained and evaluated strictly on timestamped Sysmon event logs:

| Dataset | Role in Pipeline | Description / Split Allocation |
|:---|:---|:---|
| **Splunk Attack Data** (6 files) | Attack telemetry (2,785 windows) | Sysmon logs covering MITRE techniques T1059.001 (PowerShell execution $\to$ Test), T1105 (Ingress Tool Transfer $\to$ Train), T1486 (Dcrypt / SamSam $\to$ Train/Val), T1490 (Shadow copy wipe / notes $\to$ Train). |
| **SILRAD-1.0** (`fasttext-all-nofamily.csv`) | Benign baseline (17,617 windows) | Genuine Windows 11 telemetry adapted via `SILRADAdapter` across Train (10,569), Validation (3,526), and Test (3,522). |

### Dataset Accounting & Exclusions

Auxiliary datasets present in `data/datasets/` were intentionally excluded from model training based on technical schema incompatibility:
- **RansomSet** (19 files): Windows Native API call sequence traces (`NtClose;NtOpenKey;...`), incompatible with the 17-feature Sysmon sliding-window schema.
- **CSU Ransomware** (12 files): Pre-aggregated static summary tables without temporal event logs or process identifiers.
- **MLRAN** (88 files): Cuckoo sandbox execution metadata, PE hashes, and static AVClass labels rather than streaming Sysmon logs.

---

## Installation & Setup

1. **Clone the repository:**
   ```bash
   git clone https://github.com/arc427/Behavioral-Ransomware-Detection-System-.git
   cd Behavioral-Ransomware-Detection-System-
   ```

2. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

3. **Configure environment variables:**
   ```bash
   cp .env.example .env
   ```
   Set your local API key and HMAC secret:
   ```powershell
   # Development & Evaluation mode (uses dev HMAC key):
   $env:BRDS_ALLOW_INSECURE_DEV_HMAC = "1"
   $env:BRDS_API_KEY = "dev-hmac-key"

   # Production / Live Armed mode:
   # $env:BRDS_API_KEY = "your-production-api-key"
   # $env:BRDS_ALERT_HMAC_KEY = "your-production-hmac-key"
   ```

4. **Initialize database and seed baseline data:**
   ```bash
   python scripts/run_pipeline.py
   python scripts/prepare_live_data.py
   ```

5. **Start the backend REST API:**
   ```bash
   python backend/app.py
   ```

6. **Open the SOC dashboard:**
   Open `frontend/index.html` in any web browser.

7. **Run automated test suite:**
   ```bash
   python -m pytest tests/ -v
   ```

---

## Requirements

| Requirement | Specification |
|:---|:---|
| **OS** | Windows 10 / Windows 11 |
| **Python** | 3.14+ |
| **RAM** | 8 GB minimum (16 GB recommended) |
| **GPU** | Optional (NVIDIA CUDA for faster LSTM training) |
| **Sysmon** | v15+ (with `sysmon_config/sysmon_config.xml` for live telemetry ingestion) |

---

## Documentation

Comprehensive project documentation, mathematical audits, and external evaluation reports are available in [`docs/`](docs/):

- [Cross-Source SILRAD Validation Report](docs/evaluation/Cross_Source_SILRAD_Validation.md) — External cross-source evaluation methodology and metrics
- [Forensic Metric Audit Report](docs/evaluation/SILRAD_METRIC_AUDIT.md) — Mathematical verification of ROC-AUC, PR-AUC, and screening recall
- [Evaluation Results JSON](docs/evaluation/silrad_cross_source_eval_results.json) — Raw scored window metrics and threshold logs
- [Environment Configuration Guide](.env.example) — Complete runtime environment variables, flags, and containment modes

---

## License & Safety Notice

This project is intended for educational and research purposes.

> ⚠️ Always ensure all malware testing is conducted inside isolated, non-production virtual machine sandboxes with host-only networking and snapshot recovery enabled.

