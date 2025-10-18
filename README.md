# Gmail Manager Script

This script runs periodically (e.g. every 20 minutes) to manage your incoming emails in GMail.

## Setup instructions

```bash
cp ./com.marcus.email_manager.plist ~/Library/LaunchAgents/com.marcus.email_manager.plist

launchctl load ~/Library/LaunchAgents/com.marcus.email_manager.plist
```

```bash
launchctl load ~/Library/LaunchAgents/com.marcus.email_manager.plist

launchctl list | grep marcus

launchctl unload ~/Library/LaunchAgents/com.marcus.email_manager.plist

plutil -lint ~/Library/LaunchAgents/com.marcus.email_manager.plist

sudo nano /etc/newsyslog.conf
```

### Install requirements

MacOS:
`source .venv/bin/activate`

Windows (Command Prompt):
`.venv\Scripts\activate.bat`

Windows (PowerShell):
`.venv\Scripts\Activate.ps1`

Install the requirements:
`pip install -r requirements.txt`

Deactivate when done:
`deactivate`

### Run Tests

`python3 -m pytest -q`

### Private Config

Create a `config.private.json` file (ignored by git) with your sheet settings:

```json
{
  "SPREADSHEET_ID": "YOUR_SHEET_ID_HERE",
  "SHEET_NAME": "Rules"
}
```

Alternatively, set environment variables `SPREADSHEET_ID` and/or `SHEET_NAME`. Precedence for each is: env var, then `config.private.json`, then built-in default.
