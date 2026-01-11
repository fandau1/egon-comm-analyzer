# Egon Comunication Analyzer
Egon Communication Analyzer is a tool for capturing, analyzing, and correlating UART and network communication in the ABB Ego-n intelligent smart home.

- Reads communication on the TCP/IP port `10001` exposed by the communication module.
- Monitors communication on the secondary bus (UART speed `9600`).

## Quick start (Windows)

**Prerequizite:**
- installed Python

1. Create and activate a virtualenv (optional):

```cmd
python -m venv .venv
.venv\Scripts\activate
```

2. Install dependencies:

```cmd
pip install -r requirements.txt
```

3. Run the app:

```cmd
python main.py
```

