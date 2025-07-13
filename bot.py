#!/usr/bin/env python3
"""
mw2discord.py
-------------

Report MediaWiki recent changes to a Discord channel.

Usage examples
~~~~~~~~~~~~~~
Continuous (default):
    python mw2discord.py --state-dir ./state

Cron (run every 15 min from crontab):
    */15 * * * * /usr/bin/python3 /path/to/mw2discord.py --mode cron --state-dir /var/lib/mwbot

All options:
    python mw2discord.py --help
"""
from __future__ import annotations

import argparse
import json
import logging
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List

import requests
import http.cookiejar as cookiejar
from discord import SyncWebhook, HTTPException

###############################################################################
# Configuration
###############################################################################
CONFIG = {
    # MediaWiki
    "wiki_api": os.getenv("MW_API", "https://example.org/w/api.php"),
    "wiki_page_base": os.getenv("MW_PAGE_BASE", "https://example.org/wiki/"),
    "bot_user": os.getenv("MW_BOT_USER", "MyBot@MyBot"),  # format: USERNAME@BotPasswordName
    "bot_pass": os.getenv("MW_BOT_PASS", "BotPasswordHere"),

    # Discord
    "discord_webhook": os.getenv("DISCORD_WEBHOOK", "https://discord.com/api/webhooks/..."),
    "discord_username": os.getenv("DISCORD_USERNAME", "MediaWiki Bot"),
    "discord_avatar": os.getenv("DISCORD_AVATAR", ""),

    # Behaviour
    "mode": os.getenv("MODE", "continuous"),            # "continuous" or "cron"
    "poll_interval": os.getenv("POLL_INTERVAL", 60),             # seconds (continuous mode only)
    "state_dir": os.getenv("STATE_DIR", "./state"),          # directory for cookies & last_rcid

    # Discord back-off
    "initial_backoff": 2,            # seconds
    "max_backoff": 120,              # seconds
}

###############################################################################
# Helpers                                                                     #
###############################################################################


def load_state(path: Path) -> int:
    """Load the last rcid we processed, or 0 if none."""
    try:
        return int(path.read_text().strip())
    except (FileNotFoundError, ValueError):
        return 0


def save_state(path: Path, rcid: int) -> None:
    path.write_text(str(rcid))


def mw_login(session: requests.Session, cfg: Dict[str, str]) -> None:
    """Log in (or reuse existing cookies) with BotPassword; store cookies on disk."""
    cookies_file = Path(cfg["state_dir"]) / "cookies.lwp"
    session.cookies = cookiejar.LWPCookieJar(str(cookies_file))

    # Try to reuse cookies first
    try:
        session.cookies.load(ignore_discard=True, ignore_expires=True)
    except FileNotFoundError:
        pass

    # Check if we're already logged in
    r = session.get(cfg["wiki_api"], params={"action": "query", "meta": "userinfo", "format": "json"})
    if r.ok and r.json().get("query", {}).get("userinfo", {}).get("id", 0) != 0:
        logging.info("Re-using existing session cookies.")
        return

    logging.info("Logging in fresh with BotPassword …")
    # Step 1: fetch login token
    token_r = session.get(
        cfg["wiki_api"],
        params={"action": "query", "meta": "tokens", "type": "login", "format": "json"},
    )
    token_r.raise_for_status()
    login_token = token_r.json()["query"]["tokens"]["logintoken"]

    # Step 2: login
    login_r = session.post(
        cfg["wiki_api"],
        data={
            "action": "login",
            "lgname": cfg["bot_user"],
            "lgpassword": cfg["bot_pass"],
            "lgtoken": login_token,
            "format": "json",
        },
    )
    login_r.raise_for_status()
    if login_r.json()["login"]["result"] != "Success":
        raise RuntimeError(f"Login failed: {login_r.json()}")

    session.cookies.save(ignore_discard=True, ignore_expires=True)
    logging.info("Login successful; cookies saved.")


def fetch_recent_changes(session: requests.Session, cfg: Dict[str, str], last_rcid: int) -> List[Dict]:
    """Return all RC entries *newer* than last_rcid (oldest-first order)."""
    params = {
        "action": "query",
        "list": "recentchanges",
        "rcprop": "title|ids|comment|user|timestamp",
        "rclimit": "500",
        "rcdir": "older",  # newest first
        "format": "json",
    }

    newest_first: List[Dict] = []
    keep_fetching = True
    continue_token = None

    while keep_fetching:
        if continue_token:
            params["rccontinue"] = continue_token

        r = session.get(cfg["wiki_api"], params=params, timeout=30)
        r.raise_for_status()
        data = r.json()

        batch = data["query"]["recentchanges"]
        for rc in batch:
            if rc["rcid"] <= last_rcid:
                keep_fetching = False
                break
            newest_first.append(rc)

        continue_token = data.get("continue", {}).get("rccontinue")
        if not continue_token:
            break

    # reverse so we emit oldest-first
    return list(reversed(newest_first))


# ---------------------------------------------------------------------------#
# Single "latest change" helper – used for first-run initialisation          #
# ---------------------------------------------------------------------------#

def fetch_latest_change(session: requests.Session, cfg: Dict[str, str]) -> Dict | None:
    """
    Fetch **only** the newest entry from recentchanges (rcdir=older + rclimit=1).
    Returns a dict (like those in fetch_recent_changes) or None when no edits exist.
    """
    r = session.get(
        cfg["wiki_api"],
        params={
            "action": "query",
            "list": "recentchanges",
            "rcprop": "title|ids|comment|user|timestamp",
            "rcdir": "older",    # newest first
            "rclimit": "1",
            "format": "json",
        },
        timeout=30,
    )
    r.raise_for_status()
    changes = r.json()["query"]["recentchanges"]
    return changes[0] if changes else None


def discord_send(webhook: SyncWebhook, message: str, cfg: Dict[str, str]) -> None:
    """Send a message with exponential back-off on HTTP 429."""
    delay = cfg["initial_backoff"]
    while True:
        try:
            webhook.send(message, username=cfg["discord_username"], avatar_url=(cfg["discord_avatar"] if cfg["discord_avatar"] else None), wait=False)
            return
        except HTTPException as exc:
            if exc.status != 429:
                raise
            retry_after = (
                exc.response.headers.get("Retry-After")
                or exc.response.json().get("retry_after")
                or delay
            )
            retry_after = float(retry_after)
            logging.warning("Discord rate-limited; retrying in %.1f s …", retry_after)
            time.sleep(retry_after)
            delay = min(delay * 2, cfg["max_backoff"])


def build_discord_message(rc: Dict, cfg: Dict[str, str]) -> str:
    user = rc["user"]
    title = rc["title"]
    page_url = f'{cfg["wiki_page_base"]}{title.replace(" ", "_")}'
    diff_url = f'{cfg["wiki_page_base"]}?diff={rc["revid"]}'
    summary = rc.get("comment") or "(no summary)"
    return f"**{user}** edited **[{title}](<{page_url}>)** ({summary}) \n<{diff_url}>"


###############################################################################
# Main loop / entry point                                                     #
###############################################################################


def run_once(session: requests.Session, webhook: SyncWebhook, cfg: Dict[str, str], state_path: Path) -> None:
    last_rcid = load_state(state_path)
    changes = fetch_recent_changes(session, cfg, last_rcid)
    if not changes:
        logging.info("No new changes.")
        return

    for rc in changes:
        msg = build_discord_message(rc, cfg)
        discord_send(webhook, msg, cfg)
        last_rcid = max(last_rcid, rc["rcid"])
        logging.info("Sent: %s", msg)

    save_state(state_path, last_rcid)


def parse_args() -> Dict[str, str]:
    p = argparse.ArgumentParser(description="Report MediaWiki changes to Discord.")
    p.add_argument("--mode", choices=["continuous", "cron"], default=CONFIG["mode"])
    p.add_argument("--poll-interval", type=int, default=CONFIG["poll_interval"])
    p.add_argument("--state-dir", default=CONFIG["state_dir"])
    args = p.parse_args()
    return vars(args)


def main() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    cli_cfg = parse_args()
    cfg = {**CONFIG, **cli_cfg}

    # Prepare state dir
    state_dir = Path(cfg["state_dir"]).expanduser()
    state_dir.mkdir(parents=True, exist_ok=True)
    state_path = state_dir / "last_rcid.txt"

    # HTTP session & login
    session = requests.Session()
    mw_login(session, cfg)

    # Discord webhook
    webhook = SyncWebhook.from_url(cfg["discord_webhook"])

    # -------------------------------------------------------------------#
    #  First-run semantics when no state file exists                      #
    # -------------------------------------------------------------------#

    first_run = not state_path.exists()
    if first_run:
        latest = fetch_latest_change(session, cfg)
        if latest:                               # None only on brand-new wiki
            if cfg["mode"] == "continuous":
                # Continuous: baseline at *startup* – ignore earlier edits.
                save_state(state_path, latest["rcid"])
                logging.info(
                    "Initial start (continuous): baseline set to rcid=%s; "
                    "no historical edits will be sent.",
                    latest["rcid"],
                )
            else:  # cron mode
                # Cron: on very first run send *exactly* the latest edit, then exit.
                msg = build_discord_message(latest, cfg)
                discord_send(webhook, msg, cfg)
                save_state(state_path, latest["rcid"])
                logging.info(
                    "Initial start (cron): sent newest single edit rcid=%s; done.",
                    latest["rcid"],
                )
                return

    if cfg["mode"] == "cron":
        run_once(session, webhook, cfg, state_path)
        return

    logging.info("Entering continuous mode (interval=%s s)…", cfg["poll_interval"])
    while True:
        try:
            run_once(session, webhook, cfg, state_path)
        except Exception as e:  # broad catch so the loop keeps running
            logging.exception("Error during polling: %s", e)
        time.sleep(cfg["poll_interval"])


if __name__ == "__main__":
    # Ensure we always run in UTC for timestamps; MediaWiki API expects UTC
    os.environ["TZ"] = "UTC"
    if hasattr(time, "tzset"):
        time.tzset()
    main()
