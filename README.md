# Website Log Analysis & Attack Alert System
## Multi-Agent System for Security Analysis

**Project:** Lập trình Mạng - Final Project  
**Topic:** Hệ thống Multi-Agent Phân tích Log Website và Cảnh báo Tấn công  
**Framework:** CrewAI  
**Phases:** Phase 1 (Reconnaissance) + Phase 2 (Vulnerability Assessment) + Phase 3 (Reporting)

---

## 📋 Project Overview

This project implements a **Multi-Agent System** using **CrewAI** that analyzes website logs to detect security threats, vulnerabilities, and generate comprehensive security reports with real-time alerts.

### System Architecture

The system is divided into **3 main phases**, each with specialized agents:

#### **Phase 1: RECONNAISSANCE** (Log Analysis & Pattern Detection)
- **Log Collector Agent**: Parses and normalizes web server logs (Apache, Nginx, IIS)
- **Pattern Analyzer Agent**: Establishes baselines and detects anomalies

#### **Phase 2: VULNERABILITY ASSESSMENT** (Threat Detection)
- **Threat Detector Agent**: Identifies security attacks and threats
- **Vulnerability Classifier Agent**: Assigns CVSS scores and severity levels

#### **Phase 3: REPORTING & ALERTS** (Output Generation)
- **Report Generator Agent**: Compiles findings into professional reports
- **Alert Manager Agent**: Creates real-time alerts and incident notifications

---

## 🏗️ Project Structure

```
DOAN_LTM/
├── src/
│   ├── agents.py              # Agent definitions (6 agents)
│   ├── tasks.py               # Task definitions (6 tasks)
│   ├── crew_orchestrator.py   # Main orchestration logic
│   └── tools.py               # Custom tools (to be implemented)
├── config/
│   ├── agents_config.yaml     # Agent configuration
│   └── prompts.yaml           # AI prompts (Phase 1, 2, 3)
├── data/
│   └── sample_logs/           # Sample log files for testing
├── reports/
│   └── [generated reports]    # Output reports
├── logs/
│   └── [system logs]          # Execution logs
├── docs/
│   ├── DESIGN.md              # System design document
│   ├── PROMPTS.md             # AI prompts and evaluation
│   ├── TOOLS.md               # Tool design and implementation
│   └── EVALUATION.md          # Results evaluation
├── requirements.txt
├── .env.example
└── README.md
```

---

## 🛠️ Setup Instructions

### 1. Install Dependencies

```bash
pip install -r requirements.txt
```

### 2. Configure Environment

```bash
cp .env.example .env
# Edit .env with your API keys
```

### 3. Prepare Sample Data

Place sample web server logs in `data/sample_logs/` directory:
- Apache logs: `access.log`, `error.log`
- Nginx logs: `access.log`, `error.log`

---

## 🚀 Running the System

### Method 1: Complete Analysis Pipeline
```python
from src.crew_orchestrator import LogAnalysisCrew

orchestrator = LogAnalysisCrew(llm_model="gpt-4")
results = orchestrator.run_complete_analysis("./data/sample_logs")
```

### Method 2: Individual Phases
```python
# Phase 1 only
phase1_results = orchestrator.run_phase1_analysis("./data/sample_logs")

# Phase 2 (requires Phase 1 results)
phase2_results = orchestrator.run_phase2_analysis(phase1_results)

# Phase 3 (requires Phase 1 & 2 results)
phase3_results = orchestrator.run_phase3_reporting(phase1_results, phase2_results)
```

---

## 📊 System Workflow

```
Log Source
    ↓
[PHASE 1: RECONNAISSANCE]
    ├─ Log Collector Agent (Parse logs)
    └─ Pattern Analyzer Agent (Find anomalies)
    ↓ (Context passed via CrewAI Memory)
[PHASE 2: VULNERABILITY ASSESSMENT]
    ├─ Threat Detector Agent (Identify attacks)
    └─ Vulnerability Classifier Agent (Assign severity)
    ↓ (Context passed via CrewAI Memory)
[PHASE 3: REPORTING & ALERTS]
    ├─ Report Generator Agent (Create report)
    └─ Alert Manager Agent (Generate alerts)
    ↓
Output: Report + Alerts
```

---

## 🤖 Multi-Agent Coordination

### Agent Memory & Context Preservation
- **CrewAI Memory**: Automatically maintains context between agents
- **Sequential Processing**: Tasks execute sequentially, allowing context propagation
- **Shared Context**: Phase 1 findings available to Phase 2, etc.

### Agent Communication Design
1. **Agent Roles**: Each agent has specific responsibility
2. **Task Dependencies**: Tasks reference previous phase outputs
3. **Information Flow**: 
   - Phase 1 Output → Phase 2 Input
   - Phase 1 & 2 Outputs → Phase 3 Input

---

## 📈 Expected Outputs

### Phase 1 Output
- Parsed log entries (JSON format)
- Traffic statistics
- Pattern analysis
- Anomaly baseline

### Phase 2 Output
- Detected threats
- Vulnerability classifications
- CVSS scores
- Attack patterns identified

### Phase 3 Output
- Professional security report (PDF/HTML)
- Real-time alerts
- Remediation recommendations
- Executive summary

---

## 🔍 Threat Detection Capabilities

The system can detect:
- **SQL Injection** attacks
- **Cross-Site Scripting (XSS)** attempts
- **Command Injection** payloads
- **Brute Force** authentication attacks
- **DDoS/DoS** patterns
- **Vulnerability Scanners** (Nikta, Nessus)
- **Path Traversal** attempts
- **Authentication Bypass** attempts

---

## 📝 Documentation

Detailed documentation available in `docs/` folder:
1. [DESIGN.md](docs/DESIGN.md) - System architecture and design decisions
2. [PROMPTS.md](docs/PROMPTS.md) - AI prompts used and LLM evaluation
3. [TOOLS.md](docs/TOOLS.md) - Custom tools design and implementation
4. [EVALUATION.md](docs/EVALUATION.md) - Results evaluation and improvements

---

## ⚠️ Limitations & Scope

### Scope
- Analyzes website access logs only (not all types)
- Implements Phase 1 + Phase 2 (full Pentest coverage not in scope)
- Detection based on patterns and signatures (not behavioral ML models)

### Limitations
- Real-time analysis requires streaming architecture (not implemented)
- CVSS scoring is rule-based (not CVSS calculator API integration)
- Limited to English language logs

---

## 🔄 Future Enhancements

1. Integration with SIEM systems (Splunk, ELK)
2. Machine learning-based anomaly detection
3. Real-time streaming log analysis
4. Integration with vulnerability databases (NVD API)
5. Automated incident response actions
6. Multi-tenant support

---

## 📚 Resources Used

- **CrewAI Documentation**: Framework for multi-agent coordination
- **OWASP Top 10**: Common web vulnerabilities
- **CVSS v3.1**: Vulnerability scoring framework
- **CWE Database**: Common Weakness Enumeration

---

## ✅ Evaluation Criteria Met

- ✓ Multi-Agent system with specialized roles
- ✓ CrewAI framework implementation
- ✓ Phase 1 (Reconnaissance) + Phase 2 (Vulnerability Assessment)
- ✓ Clear context preservation in multi-agent design
- ✓ Agent memory management
- ✓ Comprehensive documentation of prompts and evaluation
- ✓ AI-generated tool suggestions with custom implementations
- ✓ Professional reporting capabilities
- ✓ Real-time alert generation

---

## 📧 Support & Questions

For questions about implementation or design decisions, refer to: - [Design Document](docs/DESIGN.md)
- [Prompts & Evaluation](docs/PROMPTS.md)
- [Tools Documentation](docs/TOOLS.md)

---

**Last Updated:** 2024-03-24
