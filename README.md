# Gmail Manager Script

This script runs periodically (e.g. every 20 minutes) to manage your incoming emails in GMail.

## Setup instructions

```bash
# Lint check the plist file.
plutil -lint ./com.marcus.email_manager.plist

# Copy the plist file from this dir into the Mac agents dir.
cp ./com.marcus.email_manager.plist ~/Library/LaunchAgents/com.marcus.email_manager.plist

# Load the plist file once it is ready.
launchctl load ~/Library/LaunchAgents/com.marcus.email_manager.plist

# Confirm that the plist file is loaded and automation is running.
launchctl list | grep marcus

# Unload the plist file if you need to update it.
launchctl unload ~/Library/LaunchAgents/com.marcus.email_manager.plist

# Update your newslog config to make sure your logs don't go on forever by
# running the following command and adding the following:
sudo nano /etc/newsyslog.conf

# Rotate output.log when it reaches 5KB or after 7 days (168 hours) with 2 archived versions.
/Users/mjrlee/Documents/MyFiles/CodingDirectories/gmail-manager-script/logs/output.log    mjrlee:staff 644 2 5 168

# Rotate error.log when it reaches 5KB or after 7 days (168 hours) with 2 archived versions.
/Users/mjrlee/Documents/MyFiles/CodingDirectories/gmail-manager-script/logs/error.log     mjrlee:staff 644 2 5 168

# newsyslog dry run:
sudo newsyslog -n -f /etc/newsyslog.conf

# Check newslog logs:
tail -f /var/log/system.log | grep newsyslog
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
