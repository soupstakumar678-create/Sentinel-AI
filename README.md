# 🛡️ Sentinel-AI: End-to-End Local Forensic Workbench

> **An AI-driven, air-gapped cybersecurity platform for automated digital forensics, threat intelligence, and incident investigation.**

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue?logo=python)](https://www.python.org/)
[![TensorFlow](https://img.shields.io/badge/TensorFlow-2.x-orange?logo=tensorflow)](https://tensorflow.org)
[![PyTorch](https://img.shields.io/badge/PyTorch-2.x-red?logo=pytorch)](https://pytorch.org)
[![HuggingFace](https://img.shields.io/badge/HuggingFace-Transformers-yellow?logo=huggingface)](https://huggingface.co)
[![XGBoost](https://img.shields.io/badge/XGBoost-Enabled-green)](https://xgboost.readthedocs.io)
[![FastAPI](https://img.shields.io/badge/Backend-FastAPI-009688?logo=fastapi)](https://fastapi.tiangolo.com)
[![Streamlit](https://img.shields.io/badge/UI-Streamlit-FF4B4B?logo=streamlit)](https://streamlit.io)
[![License: MIT](https://img.shields.io/badge/License-MIT-lightgrey)](LICENSE)

---

## 📌 Overview

In the wake of a cyberattack, organizations lose critical time—and evidence—to slow, manual investigation. **Sentinel-AI** is a **locally-hosted, multi-engine AI platform** that automates digital forensics end-to-end.

It ingests raw network logs (`.pcap`, `.csv`), suspicious binaries, URLs, and social media text, then processes them through four specialized deep learning engines to produce a **Structured Forensic Investigation Report** in under 3 minutes — ready for law enforcement, executive boards, or legal compliance.

Unlike cloud-based security tools, Sentinel-AI operates entirely on your own infrastructure. **No data ever leaves your network.**

---

## 🎯 Key Metrics & Goals

| Goal | Target |
|---|---|
| Network Intrusion Detection (CICIDS 2017) | **> 95% accuracy** |
| Malware Classification (EMBER-style features) | **> 90% accuracy** |
| Time-to-Insight (full forensic summary) | **< 3 minutes** |
| Zero-Day Detection | Unsupervised anomaly flagging via Isolation Forests |
| Deployment | 100% local, air-gapped, no internet dependency |

---

## 🧠 Core Engines

### 1. 🌐 Network Traffic Analyzer
- **Models:** XGBoost + LSTM
- **Task:** Binary classification of network flows — `Benign` vs. `DDoS-Attack` / `Brute Force`
- **Dataset:** CICIDS 2017 (or high-fidelity synthetic fallback)
- **Features:** 25 traffic metrics (packet rates, byte sizes, flow durations)
- **Pipeline:** Stratified 70/15/15 split → Median imputation → StandardScaler → XGBoost with early stopping

### 2. 🦠 Malware Investigation Engine
- **Models:** XGBoost (multi-class) + CNN (planned)
- **Task:** 8-class malware family classification
- **Classes:** `Adware`, `Backdoor`, `Benign`, `Downloader`, `Ransomware`, `Spyware`, `Trojan`, `Worm`
- **Features:** 171 sandbox static/dynamic behavioral metrics (EMBER-style)
- **Config:** `multi:softprob` objective, L1/L2 regularization, 1000 estimators, early stopping

### 3. 🔍 Cyber-NLP Intelligence Engine
- **Model:** Fine-tuned `distilbert-base-uncased` (HuggingFace Transformers)
- **Tasks:**
  - Phishing URL detection (binary classification)
  - Social media crime coordination analysis
- **Training:** 4 epochs, `lr=3e-5`, weight decay `0.15`, with 10% label noise for realism
- **Input:** Raw URLs and text strings; outputs threat probability scores

### 4. 🚨 Anomaly Discovery Layer (Zero-Day Detection)
- **Models:** Isolation Forest + Autoencoders
- **Task:** Unsupervised detection of attack patterns absent from training data
- **Purpose:** Flags novel, signature-less threats that supervised models would miss

---

## 📊 Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Streamlit Dashboard (UI)                  │
│         Upload: pcap logs / binaries / URLs / text          │
└──────────────────────────┬──────────────────────────────────┘
                           │ REST API
┌──────────────────────────▼──────────────────────────────────┐
│                  FastAPI Local Backend                       │
├──────────────┬────────────────┬──────────────┬──────────────┤
│  Network     │    Malware     │  Cyber-NLP   │  Anomaly     │
│  Analyzer    │  Investigator  │  Engine      │  Discovery   │
│ (XGBoost +   │ (XGBoost CNN)  │ (DistilBERT) │ (Autoencoder │
│   LSTM)      │                │              │  + IsoForest)│
└──────────────┴────────────────┴──────────────┴──────────────┘
                           │
┌──────────────────────────▼──────────────────────────────────┐
│              Automated Forensic Report Generator             │
│   Attack Timeline · Malware Category · Evidence Summary      │
│                  Output: PDF / JSON                          │
└─────────────────────────────────────────────────────────────┘
```

---

## 🗂️ Project Structure

```
sentinel-ai/
│
├── data/                        # Raw & processed datasets (gitignored)
│   ├── network/                 # CICIDS 2017 CSVs
│   └── malware/                 # EMBER / sandbox feature files
│
├── engines/
│   ├── network_analyzer.py      # XGBoost + LSTM traffic classifier
│   ├── malware_engine.py        # Multi-class malware classifier
│   ├── nlp_engine.py            # DistilBERT phishing/social media detector
│   └── anomaly_engine.py        # Isolation Forest + Autoencoder
│
├── models/                      # Saved model weights (gitignored)
│   ├── network_model.json
│   ├── malware_model.json
│   └── sentinel_nlp_weights/
│
├── api/
│   └── main.py                  # FastAPI backend & REST endpoints
│
├── dashboard/
│   └── app.py                   # Streamlit UI
│
├── reports/
│   └── report_generator.py      # PDF forensic report builder
│
├── notebooks/
│   └── sentinel-ai-workbench.ipynb   # Main research & training notebook
│
├── requirements.txt
├── .gitignore
└── README.md
```

---

## ⚙️ Installation & Setup

### Prerequisites
- Python 3.10+
- pip / conda
- (Optional) NVIDIA GPU with CUDA for accelerated training

### 1. Clone the repository
```bash
git clone https://github.com/<your-username>/sentinel-ai.git
cd sentinel-ai
```

### 2. Create a virtual environment
```bash
python -m venv venv
source venv/bin/activate        # Linux/macOS
venv\Scripts\activate           # Windows
```

### 3. Install dependencies
```bash
pip install -r requirements.txt
```

### 4. Download datasets
All datasets are freely available. Place them in the `data/` directory:

| Dataset | Source | Engine |
|---|---|---|
| CICIDS 2017 | [Kaggle](https://www.kaggle.com/datasets/cicdataset/cicids2017) | Network Analyzer |
| EMBER (malware features) | [Kaggle](https://www.kaggle.com/datasets/ang3loliveira/malware-analysis) | Malware Engine |
| Phishing URLs | [UCI ML Repository](https://archive.ics.uci.edu/dataset/327/phishing+websites) | NLP Engine |

> **Note:** Each engine gracefully falls back to high-fidelity synthetic data if no dataset is attached — ideal for demos and development.

---

## 🚀 Running Sentinel-AI

### Start the FastAPI backend
```bash
uvicorn api.main:app --host 0.0.0.0 --port 8000
```

### Launch the Streamlit dashboard
```bash
streamlit run dashboard/app.py
```

Open your browser at `http://localhost:8501`

### Run individual engines (notebook)
Open `notebooks/sentinel-ai-workbench.ipynb` in Jupyter or Google Colab and execute cells sequentially.

---

## 📓 Training on Google Colab (GPU)

For GPU-accelerated training of the DistilBERT NLP engine and deep learning models:

1. Upload `notebooks/sentinel-ai-workbench.ipynb` to [Google Colab](https://colab.research.google.com)
2. Set runtime to **GPU** (T4 recommended)
3. Mount your Kaggle dataset or use the built-in synthetic fallback
4. Run all cells; download saved model weights to `models/`

> **Cost:** ~₹1,099/month for Colab Pro (optional; free tier works for smaller experiments)

---

## 🛡️ Security & Privacy

- **Air-gapped by design:** FastAPI backend has zero external API calls. All inference runs locally.
- **No telemetry:** No usage data is sent anywhere.
- **Anti-leakage pipeline:** All preprocessing scalers and imputers are fit exclusively on training splits, preventing data leakage across engines.
- **Suitable for:** Classified networks, legal evidence handling, regulated industries (HIPAA, SOC 2 environments).

---

## 📄 Forensic Report Output

After analysis, Sentinel-AI generates a structured PDF report containing:

- **Executive Summary** — High-level attack narrative
- **Attack Timeline** — Reconstructed sequence of events with timestamps
- **Threat Classification Table** — Malware families and confidence scores
- **Network Anomaly Map** — Flagged IP ranges and traffic patterns
- **Evidence Log** — Raw indicators of compromise (IoCs)
- **Recommendations** — Suggested remediation steps

Reports are formatted for both **law enforcement submission** and **executive board review**.

---

## 🗓️ Development Timeline

| Week | Milestones |
|---|---|
| **Week 1** | Environment setup · Dataset collection · Network Traffic Analyzer · Phishing Evidence Analyzer |
| **Week 2** | Malware Investigation Engine · Social Media Crime Detector · Zero-Day Anomaly Detection Layer |
| **Week 3** | Model evaluation · Forensic report generator · Performance optimization & hyperparameter tuning |
| **Week 4** | Streamlit dashboard · FastAPI REST endpoints · Local deployment · Documentation · Final submission |

---

## 🧰 Tech Stack

| Category | Tools |
|---|---|
| **Languages** | Python 3.10+ |
| **ML / Classical** | Scikit-learn, XGBoost, Isolation Forest |
| **Deep Learning** | TensorFlow, PyTorch |
| **NLP** | HuggingFace Transformers (DistilBERT), NLTK |
| **UI** | Streamlit |
| **Backend** | FastAPI |
| **DevOps** | GitHub, Google Colab (GPU training) |
| **Data** | Kaggle, UCI ML Repository |

---

## ⚠️ Known Challenges & Mitigations

| Risk | Mitigation |
|---|---|
| **Class imbalance** in attack datasets | SMOTE oversampling + class-weight balancing |
| **Model overfitting** on training logs | Cross-validation, L1/L2 regularization, early stopping |
| **Compute constraints** for deep learning | GPU training via Colab; local deployment uses saved weights only |
| **Scope creep** across 4 weeks | Modular architecture — one engine per development sprint |

---

## 💰 Cost Breakdown

| Resource | Cost |
|---|---|
| All datasets (Kaggle / UCI) | Free |
| All frameworks & libraries | Free (Open Source) |
| Google Colab Pro (GPU training) | ₹1,099 / month |
| Local deployment & inference | Free |
| **Total** | **~₹1,099** |

---

## 👥 Team & Acknowledgements

- **Faculty Mentor:** Sabyasachi (SoFS) — Faculty In-Charge / Primary Mentor
- Datasets: CICIDS 2017, EMBER Malware Dataset, UCI Phishing URLs
- Models: HuggingFace `distilbert-base-uncased`

---

## 📃 License

This project is licensed under the [MIT License](LICENSE). See `LICENSE` for details.

---

> *Sentinel-AI is designed for authorized forensic use by certified security professionals on systems they own or have explicit permission to analyze. Misuse of this tool for unauthorized access or surveillance is strictly prohibited.*
