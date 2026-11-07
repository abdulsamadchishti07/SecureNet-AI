# SecureNet AI: Intelligent Network Threat Detection & Response

**Author:** Abdul Samad Chishti, BS Information Technology, Islamia University Bahawalpur
**Type:** in progress

## What It Is

SecureNet AI is a network intrusion detection and response system. It watches live network traffic, uses machine learning to decide whether the traffic is normal or an attack, identifies the type of attack, and responds by blocking the attacker, logging evidence, and alerting an administrator.

Most student security projects only detect. This one is designed to detect and then act.

## The Problem

Networks are constantly scanned, flooded and probed. Fixed rules like "block anyone sending more than X packets" fail, because the same number of packets can be normal (streaming a video) or malicious (a flood attack) depending on the pattern. The system needs to recognise patterns, not just count packets.

## How It Works

1. **Capture:** A Linux machine (a Raspberry Pi in the final demo, a laptop during development) sits between the router and the connected devices. It listens to the traffic passing through using Scapy, a Python packet library.
2. **Feature extraction:** Individual packets are grouped into flows (a conversation between two machines). For each flow it computes 20 features, such as duration, packet counts, packet rates, packet sizes and TCP flag counts.
3. **Classification:** A trained machine learning model reads those features and labels the flow as normal traffic or a specific attack type.
4. **Response:** A FastAPI backend receives the verdict and acts on it. It saves the alert to PostgreSQL, blocks the attacker's IP through the Linux firewall (iptables), sends an SMS or email alert, and pushes the event to the dashboard in real time.
5. **Dashboard:** A web interface shows live alerts, attack statistics, blocked IPs and forensic logs.

The machine learning model only classifies. The backend makes the decisions and takes the actions.

## Machine Learning Details

- **Dataset:** CICIDS2017, published by the Canadian Institute for Cybersecurity at the University of New Brunswick. It contains labelled real network traffic with normal activity and several attack families.
- **Features:** 20 flow-level features chosen from the original 80+, for example Flow Duration, Flow Packets/s, SYN/ACK/RST/FIN flag counts and Average Packet Size. IP addresses and timestamps are deliberately excluded so the model learns behaviour rather than memorising attackers.
- **Class imbalance:** Normal traffic heavily outnumbers attacks in the raw data. This is handled by undersampling normal traffic and applying SMOTE to the rarest attack classes. Models are judged on precision, recall, F1-score and confusion matrices rather than accuracy alone, because a model that predicts "normal" for everything would still score about 52% accuracy.
- **Models:** Random Forest is the primary model and XGBoost is the comparison. The better one by macro F1 is deployed.

## Attack Types Covered

- **Currently trained (Friday data):** Normal, Port Scan, DDoS, Botnet
- **Planned expansion:** Brute Force (SSH/FTP), DoS variants, Web Attacks. This needs Tuesday, Wednesday and Thursday data, and some very rare classes (Heartbleed, SQL injection, Infiltration) will be dropped because there are too few samples to learn from.

## Tech Stack

| Area             | Technology                                             |
| ---------------- | ------------------------------------------------------ |
| Language         | Python 3.11+                                           |
| Packet capture   | Scapy                                                  |
| Machine learning | scikit-learn, XGBoost, pandas, NumPy, imbalanced-learn |
| Backend          | FastAPI, SQLAlchemy, JWT authentication                |
| Database / queue | PostgreSQL, Redis                                      |
| Alerts           | Twilio (SMS), SMTP (email)                             |
| Dashboard        | React / Next.js, Tailwind CSS, WebSockets              |
| Hardware         | Raspberry Pi 4 (final deployment)                      |
| Deployment       | Docker, Docker Compose, Git/GitHub                     |

## Testing Plan

A virtual lab built in VirtualBox with three machines: an attacker (Kali Linux), a victim (Ubuntu Server) and the SecureNet system. Attacks are launched with Nmap (port scans), Hydra (brute force) and hping3 (flood attacks) to verify the system detects and blocks them in real time.

## Current Status

| Component                                         | Status             |
| ------------------------------------------------- | ------------------ |
| Data preprocessing (cleaning, balancing, scaling) | Done (Friday data) |
| Model training (Random Forest, XGBoost)           | Done (Friday data) |
| Model evaluation (reports, confusion matrices)    | Done (Friday data) |
| Expanding training to all attack types            | Planned            |
| Packet sniffer and flow feature extraction        | Next               |
| FastAPI backend, database, auto-blocking          | Planned            |
| Dashboard                                         | Planned            |
| Virtual attack lab and live testing               | Planned            |

## Known Limitations

- The model is trained on a public dataset, so it has not yet been validated on live traffic. Live validation is part of the lab testing phase.
- Some attack classes rely on synthetic samples generated by SMOTE because the real examples are scarce.
- Converting live packets into the same flow features the dataset uses is the hardest engineering step, and it is still in progress.

## Dataset

The CICIDS2017 CSV files are not included in this repository because of their size. Download them from the Canadian Institute for Cybersecurity (University of New Brunswick) and place them in `dataset/raw/`.

## Running the ML Engine

```bash
pip install -r requirements.txt
python -m ml_engine.preprocess
python -m ml_engine.train
python -m ml_engine.evaluate
```
