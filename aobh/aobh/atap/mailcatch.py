#!/usr/bin/env python3
"""mailcatch.py — verification-mail acquisition for ATAP.

Three strategies for getting signup/verification mail:

  catcher  — minimal asyncio SMTP catcher bound to 127.0.0.1. For local labs and
             any target that can deliver to an address whose MX points at the
             operator's host (or when the target's SMTP is the sandbox itself).
  imap     — poll a REAL mailbox the operator provides (e.g. a dedicated test
             inbox, ideally with plus-addressing `user+accNN@host`) via IMAP.
             The normal choice for real bug bounty targets.
  manual   — the human completes email steps and pastes the verification link.

Links (verification URLs) are extracted automatically from message bodies.
stdlib only; the catcher handles EHLO/HELO, MAIL, RCPT, DATA (incl. dot-stuffing),
RSET, NOOP, QUIT — enough for real MTAs and the test harness.
"""
from __future__ import annotations

import asyncio
import email as email_lib
import email.utils
import json
import re
import time
from email.header import decode_header
from pathlib import Path

LINK_RE = re.compile(r"""https?://[^\s"'<>()\[\]{}]+""", re.I)


def extract_links(text: str) -> list[str]:
    if not text:
        return []
    body = text.replace("&amp;", "&")
    seen, out = set(), []
    for m in LINK_RE.findall(body):
        url = m.rstrip(".,;:!?")
        if url not in seen:
            seen.add(url)
            out.append(url)
    return out


class MailCatcher:
    """Local SMTP catcher. Every accepted message lands in `self.messages`."""

    def __init__(self, host: str = "127.0.0.1", port: int = 8025, mail_dir: str | Path | None = None):
        self.host, self.port = host, port
        self.mail_dir = Path(mail_dir) if mail_dir else None
        self.messages: list[dict] = []
        self._server: asyncio.AbstractServer | None = None
        if self.mail_dir:
            self.mail_dir.mkdir(parents=True, exist_ok=True)

    # ---------- SMTP protocol (asyncio streams) ----------
    async def _client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            peer = writer.get_extra_info("peername")
            sender, recipients, data_lines = None, [], []
            state = "cmd"
            writer.write(b"220 atap-mailcatcher ready\r\n")
            await writer.drain()
            while True:
                line = await asyncio.wait_for(reader.readline(), timeout=120)
                if not line:
                    break
                if state == "data":
                    if line.strip() == b".":
                        self._ingest(sender, recipients, b"\n".join(data_lines))
                        sender, recipients, data_lines = None, [], []
                        state = "cmd"
                        writer.write(b"250 OK message accepted\r\n")
                    else:
                        data_lines.append(line[1:] if line.startswith(b".") else line)  # dot-unstuffing
                        if len(data_lines) > 5000:
                            raise ValueError("message too large")
                    await writer.drain()
                    continue
                cmd = line.strip().upper()
                if cmd.startswith(b"EHLO") or cmd.startswith(b"HELO"):
                    writer.write(b"250-atap-mailcatcher\r\n250 OK\r\n")
                elif cmd.startswith(b"MAIL FROM"):
                    sender = line.decode(errors="replace").split(":", 1)[-1].strip(" <>")
                    writer.write(b"250 OK\r\n")
                elif cmd.startswith(b"RCPT TO"):
                    recipients.append(line.decode(errors="replace").split(":", 1)[-1].strip(" <>"))
                    writer.write(b"250 OK\r\n")
                elif cmd.startswith(b"DATA"):
                    state = "data"
                    writer.write(b"354 end with <CRLF>.<CRLF>\r\n")
                elif cmd.startswith(b"RSET"):
                    sender, recipients, data_lines = None, [], []
                    writer.write(b"250 OK\r\n")
                elif cmd.startswith(b"NOOP"):
                    writer.write(b"250 OK\r\n")
                elif cmd.startswith(b"QUIT"):
                    writer.write(b"221 bye\r\n")
                    await writer.drain()
                    break
                else:
                    writer.write(b"250 OK\r\n")
                await writer.drain()
        except Exception:
            pass
        finally:
            try:
                writer.close()
            except Exception:
                pass

    def _ingest(self, sender, recipients, raw: bytes) -> None:
        raw_text = raw.decode("utf-8", errors="replace")
        msg = email_lib.message_from_string(raw_text)
        subject = ""
        try:
            parts = decode_header(msg.get("Subject", "") or "")
            subject = "".join(p.decode(cs or "utf-8", errors="replace") if isinstance(p, bytes) else p
                              for p, cs in parts)
        except Exception:
            subject = msg.get("Subject", "")
        body = raw_text
        if msg.is_multipart():
            for part in msg.walk():
                if part.get_content_type() in ("text/plain", "text/html"):
                    try:
                        body += "\n" + part.get_payload(decode=True).decode("utf-8", errors="replace")
                    except Exception:
                        body += "\n" + str(part.get_payload())
        record = {
            "id": f"m-{len(self.messages)+1:04d}",
            "ts": time.time(),
            "sender": sender or "",
            "recipients": recipients,
            "subject": subject,
            "raw_len": len(raw),
            "links": extract_links(raw_text),
            "body_preview": body[:500],
        }
        self.messages.append(record)
        if self.mail_dir:
            with (self.mail_dir / "caught_mail.jsonl").open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(record, ensure_ascii=False) + "\n")

    # ---------- lifecycle / queries ----------
    async def start(self) -> dict:
        if self._server:
            return {"host": self.host, "port": self.port, "already_running": True}
        self._server = await asyncio.start_server(self._client, self.host, self.port)
        if self.port == 0:  # ephemeral bind — record the actual port
            self.port = self._server.sockets[0].getsockname()[1]
        return {"host": self.host, "port": self.port, "already_running": False}

    async def stop(self) -> None:
        if self._server:
            self._server.close()
            await self._server.wait_closed()
            self._server = None

    def find(self, recipient_contains: str | None = None, subject_contains: str | None = None,
             since_ts: float = 0.0) -> list[dict]:
        hits = []
        for m in self.messages:
            if m["ts"] < since_ts:
                continue
            if recipient_contains and recipient_contains.lower() not in " ".join(m["recipients"]).lower():
                continue
            if subject_contains and subject_contains.lower() not in m["subject"].lower():
                continue
            hits.append(m)
        return hits

    def wait_for_message(self, recipient_contains: str | None = None,
                         subject_contains: str | None = None, since_ts: float = 0.0,
                         timeout: int = 90) -> dict | None:
        """Blocking poll — safe to call from sync tool handlers (the SMTP server
        runs on its own thread/loop and appends to self.messages)."""
        deadline = time.time() + timeout
        while time.time() < deadline:
            hits = self.find(recipient_contains, subject_contains, since_ts)
            if hits:
                return hits[-1]
            time.sleep(0.5)
        return None

    def start_in_thread(self) -> "threading.Thread":
        """Run the catcher's event loop in a daemon thread (for embedding in the
        sync MCP-server process)."""
        import threading

        def run() -> None:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            loop.run_until_complete(self.start())
            loop.run_forever()

        t = threading.Thread(target=run, daemon=True, name="atap-mailcatcher")
        t.start()
        return t


def imap_fetch_links(host: str, user: str, password: str, mailbox: str = "INBOX",
                     recipient_contains: str | None = None, since_minutes: int = 30,
                     port: int = 993) -> dict:
    """Poll a real mailbox via IMAP for recent messages; returns messages + extracted links."""
    import imaplib
    msgs = []
    conn = imaplib.IMAP4_SSL(host, port)
    try:
        conn.login(user, password)
        conn.select(mailbox)
        since = email.utils.formatdate(time.time() - since_minutes * 60, localtime=False)
        status, data = conn.search(None, f'(SINCE "{email.utils.formatdate(time.time() - since_minutes*60, localtime=True)[:16]}")')
        if status == "OK":
            for num in data[0].split()[-25:]:  # cap: 25 newest
                st, parts = conn.fetch(num, "(RFC822)")
                if st != "OK":
                    continue
                msg = email_lib.message_from_bytes(parts[0][1])
                to_header = msg.get("To", "")
                if recipient_contains and recipient_contains.lower() not in to_header.lower():
                    continue
                body = ""
                if msg.is_multipart():
                    for part in msg.walk():
                        if part.get_content_type() in ("text/plain", "text/html"):
                            try:
                                body += "\n" + part.get_payload(decode=True).decode("utf-8", errors="replace")
                            except Exception:
                                pass
                else:
                    try:
                        body = msg.get_payload(decode=True).decode("utf-8", errors="replace")
                    except Exception:
                        body = str(msg.get_payload())
                msgs.append({"subject": msg.get("Subject", ""), "to": to_header,
                             "links": extract_links(msg.get("Subject", "") + "\n" + body)})
    finally:
        try:
            conn.logout()
        except Exception:
            pass
    return {"messages": msgs}
