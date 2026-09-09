import os
import requests

WEBHOOK_URL = os.getenv("ALERT_WEBHOOK_URL")


def notify_high_risk_drift(app_name: str, db_name: str, summary: str) -> None:
    """Sends a high-risk drift alert to MS Teams Workflows via Adaptive Card."""
    if not WEBHOOK_URL:
        print("[ALERT] ALERT_WEBHOOK_URL is not configured.")
        return

    # Adaptive Card Payload required by Microsoft Teams Workflows
    payload = {
        "type": "message",
        "attachments": [
            {
                "contentType": "application/vnd.microsoft.card.adaptive",
                "contentUrl": None,
                "content": {
                    "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                    "type": "AdaptiveCard",
                    "version": "1.4",
                    "msteams": {"width": "Full"},
                    "body": [
                        {
                            "type": "TextBlock",
                            "text": "🚨 HIGH RISK DRIFT DETECTED",
                            "weight": "Bolder",
                            "size": "Medium",
                            "color": "Attention",
                        },
                        {
                            "type": "FactSet",
                            "facts": [
                                {"title": "Application:", "value": app_name},
                                {"title": "Database CI:", "value": db_name},
                                {"title": "Severity:", "value": "High Risk"},
                            ],
                        },
                        {
                            "type": "TextBlock",
                            "text": "**RCA & Risk Summary:**",
                            "weight": "Bolder",
                            "spacing": "Medium",
                        },
                        {
                            "type": "TextBlock",
                            "text": summary or "Configuration drift requires immediate DBA inspection.",
                            "wrap": True,
                        },
                    ],
                },
            }
        ],
    }

    try:
        response = requests.post(
            WEBHOOK_URL,
            json=payload,
            headers={"Content-Type": "application/json"},
            timeout=5,
        )
        if response.status_code in (200, 202):
            print(f"[ALERT SUCCESS] Teams notification posted for {app_name} ({db_name})")
        else:
            print(f"[ALERT FAILED] Status code: {response.status_code}, Response: {response.text}")
    except Exception as ex:
        print(f"[ALERT ERROR]: Failed to send webhook alert: {ex}")

def notify_db2_incident(app_name: str, db_name: str, analysis_res: dict, webhook_url: str = None) -> None:
    """Sends a targeted DB2 remediation card to MS Teams Workflows containing only RCA and Staged Command."""
    target_url = webhook_url or WEBHOOK_URL
    if not target_url:
        print("[ALERT] Teams Webhook URL is not configured.")
        return

    # Extract only the needed fields
    rca = analysis_res.get("rca", "No RCA provided.")
    staged_command = analysis_res.get("staged_command", "None")

    payload = {
        "type": "message",
        "attachments": [
            {
                "contentType": "application/vnd.microsoft.card.adaptive",
                "contentUrl": None,
                "content": {
                    "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                    "type": "AdaptiveCard",
                    "version": "1.4",
                    "msteams": {"width": "Full"},
                    "body": [
                        {
                            "type": "TextBlock",
                            "text": "🚨 DB2 REMEDIATION REQUIRED",
                            "weight": "Bolder",
                            "size": "Medium",
                            "color": "Attention",
                        },
                        {
                            "type": "FactSet",
                            "facts": [
                                {"title": "Application:", "value": app_name},
                                {"title": "Database CI:", "value": db_name},
                            ],
                        },
                        {
                            "type": "TextBlock",
                            "text": "**Root Cause Analysis (RCA):**",
                            "weight": "Bolder",
                            "spacing": "Medium",
                        },
                        {
                            "type": "TextBlock",
                            "text": rca,
                            "wrap": True,
                            "spacing": "Small",
                        },
                        {
                            "type": "TextBlock",
                            "text": "**Staged Remediation Command:**",
                            "weight": "Bolder",
                            "spacing": "Medium",
                        },
                        {
                            "type": "TextBlock",
                            "text": f"```\n{staged_command}\n```",
                            "wrap": True,
                            "spacing": "Small",
                            "fontType": "Monospace",
                        },
                    ],
                },
            }
        ],
    }

    try:
        response = requests.post(
            target_url,
            json=payload,
            headers={"Content-Type": "application/json"},
            timeout=5,
        )
        if response.status_code in (200, 202):
            print(
                f"[ALERT SUCCESS] Teams notification posted for {app_name} ({db_name})"
            )
        else:
            print(
                f"[ALERT FAILED] Status code: {response.status_code}, Response: {response.text}"
            )
    except Exception as ex:
        print(f"[ALERT ERROR]: Failed to send webhook alert: {ex}")