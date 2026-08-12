#!/usr/bin/env python3
"""
SMTP Command Center
Single-file desktop SMTP manager.

Features:
- Local login/logout
- Dashboard/statistics
- Sender profiles
- Gmail/Google Workspace, Outlook, Microsoft 365, Yahoo, iCloud, Custom SMTP presets
- SSL / STARTTLS
- OS keyring credential storage
- SMTP connection tester
- Compose mail with CC/BCC/HTML/attachments
- Templates
- Drafts
- Recipient groups
- Send history
- Activity logs
- CSV export
- Security page
- User management
- Modern dark Tkinter UI

Run:
    python3 smtp_command_center.py

Optional:
    python3 -m pip install keyring
"""

import csv
import hashlib
import mimetypes
import os
import queue
import secrets
import smtplib
import sqlite3
import ssl
import threading
import tkinter as tk
from datetime import datetime
from email.message import EmailMessage
from email.utils import formataddr
from tkinter import filedialog, messagebox, ttk

try:
    import keyring
    KEYRING_AVAILABLE = True
except ImportError:
    keyring = None
    KEYRING_AVAILABLE = False


# ============================================================
# PATHS / CONSTANTS
# ============================================================

APP_NAME = "SMTP Command Center"
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "smtp_command_center.db")
LOGO_PATH = os.path.join(BASE_DIR, "logo.png")
KEYRING_SERVICE = "SMTPCommandCenter"

# Theme
BG = "#0a0f1f"
SIDEBAR = "#10172a"
CARD = "#151e33"
CARD2 = "#1d2943"
ENTRY_BG = "#0c1427"
TEXT = "#f5f7ff"
MUTED = "#91a0bb"
BLUE = "#5b8cff"
CYAN = "#22d3ee"
GREEN = "#22c55e"
RED = "#ef4444"
YELLOW = "#f59e0b"
PURPLE = "#a855f7"
BORDER = "#293653"

# SMTP presets
PROVIDERS = {
    "Gmail / Google Workspace": [
        ("smtp.gmail.com", 465, "SSL"),
        ("smtp.gmail.com", 587, "STARTTLS"),
    ],
    "Outlook.com / Hotmail": [
        ("smtp-mail.outlook.com", 587, "STARTTLS"),
    ],
    "Microsoft 365": [
        ("smtp.office365.com", 587, "STARTTLS"),
    ],
    "Yahoo Mail": [
        ("smtp.mail.yahoo.com", 465, "SSL"),
        ("smtp.mail.yahoo.com", 587, "STARTTLS"),
    ],
    "iCloud Mail": [
        ("smtp.mail.me.com", 587, "STARTTLS"),
    ],
    "Custom SMTP": [
        ("", 587, "STARTTLS"),
    ],
}


# ============================================================
# DATABASE
# ============================================================

class Database:
    def __init__(self):
        self.conn = sqlite3.connect(DB_PATH, check_same_thread=False)
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.create_tables()

    def create_tables(self):
        self.conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                salt TEXT NOT NULL,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'user',
                created TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS profiles (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT UNIQUE NOT NULL,
                provider TEXT NOT NULL,
                server TEXT NOT NULL,
                port INTEGER NOT NULL,
                security TEXT NOT NULL,
                username TEXT NOT NULL,
                sender TEXT NOT NULL,
                display_name TEXT,
                created TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                profile TEXT,
                sender TEXT,
                recipient TEXT,
                subject TEXT,
                status TEXT,
                error TEXT,
                timestamp TEXT
            );

            CREATE TABLE IF NOT EXISTS templates (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT UNIQUE NOT NULL,
                subject TEXT,
                body TEXT,
                created TEXT
            );

            CREATE TABLE IF NOT EXISTS drafts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT UNIQUE NOT NULL,
                recipient TEXT,
                cc TEXT,
                bcc TEXT,
                subject TEXT,
                body TEXT,
                html INTEGER DEFAULT 0,
                updated TEXT
            );

            CREATE TABLE IF NOT EXISTS recipient_groups (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT UNIQUE NOT NULL,
                recipients TEXT,
                created TEXT
            );

            CREATE TABLE IF NOT EXISTS logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                level TEXT,
                message TEXT,
                timestamp TEXT
            );
            """
        )
        self.conn.commit()

        if not self.conn.execute("SELECT 1 FROM users LIMIT 1").fetchone():
            self.create_user("admin", "admin", "admin")
            self.log("INFO", "First-run administrator created")

    # ---------------- USERS ----------------

    def _password_hash(self, password, salt):
        return hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            salt.encode("utf-8"),
            240000,
        ).hex()

    def create_user(self, username, password, role="user"):
        username = username.strip()
        if not username:
            raise ValueError("Username is required")
        if len(password) < 8:
            raise ValueError("Password must be at least 8 characters")

        salt = secrets.token_hex(16)
        password_hash = self._password_hash(password, salt)

        self.conn.execute(
            """
            INSERT INTO users(username, salt, password_hash, role, created)
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                username,
                salt,
                password_hash,
                role,
                datetime.now().isoformat(timespec="seconds"),
            ),
        )
        self.conn.commit()

    def verify_user(self, username, password):
        row = self.conn.execute(
            "SELECT salt, password_hash, role FROM users WHERE username=?",
            (username.strip(),),
        ).fetchone()

        if not row:
            return None

        calculated = self._password_hash(password, row[0])

        if secrets.compare_digest(calculated, row[1]):
            return row[2]

        return None

    def change_password(self, username, new_password):
        salt = secrets.token_hex(16)
        password_hash = self._password_hash(new_password, salt)

        self.conn.execute(
            """
            UPDATE users
            SET salt=?, password_hash=?
            WHERE username=?
            """,
            (salt, password_hash, username),
        )
        self.conn.commit()

    def list_users(self):
        return self.conn.execute(
            """
            SELECT id, username, role, created
            FROM users
            ORDER BY username
            """
        ).fetchall()

    def delete_user(self, user_id):
        self.conn.execute("DELETE FROM users WHERE id=?", (user_id,))
        self.conn.commit()

    # ---------------- PROFILES ----------------

    def add_profile(
        self,
        name,
        provider,
        server,
        port,
        security,
        username,
        sender,
        display_name,
    ):
        self.conn.execute(
            """
            INSERT INTO profiles
            (name, provider, server, port, security, username, sender, display_name, created)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                name,
                provider,
                server,
                int(port),
                security,
                username,
                sender,
                display_name,
                datetime.now().isoformat(timespec="seconds"),
            ),
        )
        self.conn.commit()

    def list_profiles(self):
        return self.conn.execute(
            """
            SELECT id, name, provider, server, port, security,
                   username, sender, display_name, created
            FROM profiles
            ORDER BY name
            """
        ).fetchall()

    def update_profile(self, profile_id, name, provider, server, port, security, username, sender, display_name):
        self.conn.execute("""UPDATE profiles SET name=?, provider=?, server=?, port=?, security=?, username=?, sender=?, display_name=? WHERE id=?""",
                          (name, provider, server, int(port), security, username, sender, display_name, profile_id))
        self.conn.commit()

    def delete_profile(self, profile_id):
        self.conn.execute("DELETE FROM profiles WHERE id=?", (profile_id,))
        self.conn.commit()

    # ---------------- HISTORY ----------------

    def add_history(self, profile, sender, recipient, subject, status, error=""):
        self.conn.execute(
            """
            INSERT INTO history
            (profile, sender, recipient, subject, status, error, timestamp)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                profile,
                sender,
                recipient,
                subject,
                status,
                error,
                datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            ),
        )
        self.conn.commit()

    def list_history(self):
        return self.conn.execute(
            """
            SELECT profile, sender, recipient, subject,
                   status, error, timestamp
            FROM history
            ORDER BY id DESC
            LIMIT 1000
            """
        ).fetchall()

    def stats(self):
        total = self.conn.execute(
            "SELECT COUNT(*) FROM history"
        ).fetchone()[0]
        sent = self.conn.execute(
            "SELECT COUNT(*) FROM history WHERE status='SENT'"
        ).fetchone()[0]
        failed = self.conn.execute(
            "SELECT COUNT(*) FROM history WHERE status='FAILED'"
        ).fetchone()[0]
        profiles = self.conn.execute(
            "SELECT COUNT(*) FROM profiles"
        ).fetchone()[0]

        return total, sent, failed, profiles

    # ---------------- TEMPLATES ----------------

    def list_templates(self):
        return self.conn.execute(
            """
            SELECT id, name, subject, body, created
            FROM templates
            ORDER BY name
            """
        ).fetchall()

    def save_template(self, name, subject, body):
        self.conn.execute(
            """
            INSERT OR REPLACE INTO templates
            (name, subject, body, created)
            VALUES (?, ?, ?, ?)
            """,
            (
                name,
                subject,
                body,
                datetime.now().isoformat(timespec="seconds"),
            ),
        )
        self.conn.commit()

    def edit_template(self, template):
        tid, old_name, old_subject, old_body, created=template
        dialog=tk.Toplevel(self.root); dialog.title("Edit Template"); dialog.geometry("700x560"); dialog.configure(bg=BG); dialog.transient(self.root); dialog.grab_set()
        frame=tk.Frame(dialog,bg=BG); frame.pack(fill="both",expand=True,padx=25,pady=20)
        tk.Label(frame,text="NAME",bg=BG,fg=MUTED).pack(anchor="w"); name=self.make_entry(frame); name.insert(0,old_name)
        tk.Label(frame,text="SUBJECT",bg=BG,fg=MUTED).pack(anchor="w",pady=(15,4)); subject=self.make_entry(frame); subject.insert(0,old_subject or "")
        tk.Label(frame,text="BODY",bg=BG,fg=MUTED).pack(anchor="w",pady=(15,4)); body=tk.Text(frame,bg=ENTRY_BG,fg=TEXT,insertbackground=TEXT,relief="flat",wrap="word"); body.pack(fill="both",expand=True); body.insert("1.0",old_body or "")
        def save():
            if not name.get().strip(): return messagebox.showwarning("Template","Enter a template name.",parent=dialog)
            try: self.db.update_template(tid,name.get().strip(),subject.get(),body.get("1.0","end").strip()); dialog.destroy(); self.templates_page()
            except sqlite3.IntegrityError: messagebox.showerror("Template","A template with this name already exists.",parent=dialog)
        self.make_button(frame,"SAVE CHANGES",save,GREEN).pack(fill="x",pady=12)

    def update_template(self, template_id,name,subject,body):
        self.conn.execute("UPDATE templates SET name=?, subject=?, body=?, created=? WHERE id=?",(name,subject,body,datetime.now().isoformat(timespec="seconds"),template_id)); self.conn.commit()

    def delete_template(self, template_id):
        self.conn.execute(
            "DELETE FROM templates WHERE id=?",
            (template_id,),
        )
        self.conn.commit()

    # ---------------- DRAFTS ----------------

    def list_drafts(self):
        return self.conn.execute(
            """
            SELECT id, name, recipient, cc, bcc,
                   subject, body, html, updated
            FROM drafts
            ORDER BY updated DESC
            """
        ).fetchall()

    def save_draft(self, name, recipient, cc, bcc, subject, body, html):
        self.conn.execute(
            """
            INSERT OR REPLACE INTO drafts
            (name, recipient, cc, bcc, subject, body, html, updated)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                name,
                recipient,
                cc,
                bcc,
                subject,
                body,
                int(html),
                datetime.now().isoformat(timespec="seconds"),
            ),
        )
        self.conn.commit()

    def delete_draft(self, draft_id):
        self.conn.execute(
            "DELETE FROM drafts WHERE id=?",
            (draft_id,),
        )
        self.conn.commit()

    # ---------------- GROUPS ----------------

    def list_groups(self):
        return self.conn.execute(
            """
            SELECT id, name, recipients, created
            FROM recipient_groups
            ORDER BY name
            """
        ).fetchall()

    def save_group(self, name, recipients):
        self.conn.execute(
            """
            INSERT OR REPLACE INTO recipient_groups
            (name, recipients, created)
            VALUES (?, ?, ?)
            """,
            (
                name,
                recipients,
                datetime.now().isoformat(timespec="seconds"),
            ),
        )
        self.conn.commit()

    def edit_group(self, group):
        gid,old_name,old_recipients,created=group
        dialog=tk.Toplevel(self.root); dialog.title("Edit Recipient Group"); dialog.geometry("700x520"); dialog.configure(bg=BG); dialog.transient(self.root); dialog.grab_set()
        frame=tk.Frame(dialog,bg=BG); frame.pack(fill="both",expand=True,padx=25,pady=20)
        tk.Label(frame,text="GROUP NAME",bg=BG,fg=MUTED).pack(anchor="w"); name=self.make_entry(frame); name.insert(0,old_name)
        tk.Label(frame,text="RECIPIENTS — comma separated",bg=BG,fg=MUTED).pack(anchor="w",pady=(15,4)); recipients=tk.Text(frame,bg=ENTRY_BG,fg=TEXT,insertbackground=TEXT,relief="flat",wrap="word"); recipients.pack(fill="both",expand=True); recipients.insert("1.0",old_recipients or "")
        def save():
            gn=name.get().strip(); emails=self.parse_recipients(recipients.get("1.0","end"))
            if not gn or not emails: return messagebox.showwarning("Group","Enter a name and at least one recipient.",parent=dialog)
            try: self.db.update_group(gid,gn,",".join(emails)); dialog.destroy(); self.groups_page()
            except sqlite3.IntegrityError: messagebox.showerror("Group","A group with this name already exists.",parent=dialog)
        self.make_button(frame,"SAVE CHANGES",save,GREEN).pack(fill="x",pady=12)

    def update_group(self, group_id,name,recipients):
        self.conn.execute("UPDATE groups_ SET name=?, recipients=?, created=? WHERE id=?",(name,recipients,datetime.now().isoformat(timespec="seconds"),group_id)); self.conn.commit()

    def delete_group(self, group_id):
        self.conn.execute(
            "DELETE FROM recipient_groups WHERE id=?",
            (group_id,),
        )
        self.conn.commit()

    # ---------------- LOGS ----------------

    def log(self, level, message):
        self.conn.execute(
            """
            INSERT INTO logs(level, message, timestamp)
            VALUES (?, ?, ?)
            """,
            (
                level,
                message,
                datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            ),
        )
        self.conn.commit()

    def list_logs(self):
        return self.conn.execute(
            """
            SELECT level, message, timestamp
            FROM logs
            ORDER BY id DESC
            LIMIT 1000
            """
        ).fetchall()


# ============================================================
# KEYRING
# ============================================================

def save_smtp_password(profile_name, username, password):
    if not KEYRING_AVAILABLE:
        raise RuntimeError(
            "Python keyring is not installed. Run: python3 -m pip install keyring"
        )

    keyring.set_password(
        KEYRING_SERVICE,
        f"{profile_name}:{username}",
        password,
    )


def get_smtp_password(profile_name, username):
    if not KEYRING_AVAILABLE:
        return None

    return keyring.get_password(
        KEYRING_SERVICE,
        f"{profile_name}:{username}",
    )


def delete_smtp_password(profile_name, username):
    if not KEYRING_AVAILABLE:
        return

    try:
        keyring.delete_password(
            KEYRING_SERVICE,
            f"{profile_name}:{username}",
        )
    except Exception:
        pass


# ============================================================
# APPLICATION
# ============================================================

class SMTPCommandCenter:
    def __init__(self, root):
        self.root = root
        self.db = Database()

        self.current_user = None
        self.attachments = []

        self.send_queue = queue.Queue()
        self.queue_running = False

        self.root.configure(bg=BG)
        self.root.protocol("WM_DELETE_WINDOW", self.close_app)

        self.configure_styles()
        self.show_login()

    # ---------------- GENERAL UI ----------------

    def clear_window(self):
        for widget in self.root.winfo_children():
            widget.destroy()

    def configure_styles(self):
        style = ttk.Style()

        try:
            style.theme_use("clam")
        except tk.TclError:
            pass

        style.configure(
            "Treeview",
            background=CARD,
            foreground=TEXT,
            fieldbackground=CARD,
            rowheight=32,
            borderwidth=0,
        )

        style.configure(
            "Treeview.Heading",
            background=CARD2,
            foreground=TEXT,
            font=("Segoe UI", 9, "bold"),
        )

        style.map(
            "Treeview",
            background=[("selected", BLUE)],
            foreground=[("selected", "white")],
        )

        style.configure(
            "TCombobox",
            fieldbackground=ENTRY_BG,
            background=ENTRY_BG,
            foreground=TEXT,
        )

    def make_entry(self, parent, show=None):
        entry = tk.Entry(
            parent,
            bg=ENTRY_BG,
            fg=TEXT,
            insertbackground=TEXT,
            relief="flat",
            font=("Segoe UI", 10),
            show=show or "",
        )
        entry.pack(fill="x", ipady=8)
        return entry

    def make_button(self, parent, text, command, color=BLUE):
        return tk.Button(
            parent,
            text=text,
            command=command,
            bg=color,
            fg="white",
            activebackground=color,
            activeforeground="white",
            relief="flat",
            bd=0,
            font=("Segoe UI", 9, "bold"),
            padx=14,
            pady=9,
            cursor="hand2",
        )

    def make_card(self, parent, title=None):
        frame = tk.Frame(
            parent,
            bg=CARD,
            highlightbackground=BORDER,
            highlightthickness=1,
        )

        if title:
            tk.Label(
                frame,
                text=title,
                bg=CARD,
                fg=TEXT,
                font=("Segoe UI", 12, "bold"),
            ).pack(
                anchor="w",
                padx=18,
                pady=(15, 10),
            )

        return frame

    def page_header(self, title, subtitle):
        self.page_title.config(text=title)
        self.page_subtitle.config(text=subtitle)

        for widget in self.content.winfo_children():
            widget.destroy()

    def show_tree(
        self,
        parent,
        columns,
        headings,
        rows,
        widths=None,
    ):
        frame = tk.Frame(parent, bg=CARD)
        frame.pack(fill="both", expand=True, padx=12, pady=(0, 12))

        tree = ttk.Treeview(
            frame,
            columns=columns,
            show="headings",
        )

        for index, (column, heading) in enumerate(
            zip(columns, headings)
        ):
            tree.heading(column, text=heading)

            width = (
                widths[index]
                if widths and index < len(widths)
                else 140
            )

            tree.column(
                column,
                width=width,
                minwidth=70,
                anchor="w",
            )

        scrollbar = ttk.Scrollbar(
            frame,
            orient="vertical",
            command=tree.yview,
        )

        tree.configure(yscrollcommand=scrollbar.set)

        tree.pack(
            side="left",
            fill="both",
            expand=True,
        )

        scrollbar.pack(
            side="right",
            fill="y",
        )

        for row in rows:
            tree.insert("", "end", values=row)

        return tree

    # ========================================================
    # LOGIN
    # ========================================================

    def show_login(self):
        self.clear_window()

        self.root.geometry("900x600")
        self.root.minsize(760, 520)

        container = tk.Frame(self.root, bg=BG)
        container.pack(fill="both", expand=True)

        left = tk.Frame(
            container,
            bg=SIDEBAR,
            width=420,
        )
        left.pack(side="left", fill="y")
        left.pack_propagate(False)

        if os.path.exists(LOGO_PATH):
            try:
                image = tk.PhotoImage(file=LOGO_PATH)
                image = image.subsample(
                    max(1, image.width() // 120),
                    max(1, image.height() // 120),
                )
                self.login_logo_image = image

                tk.Label(
                    left,
                    image=image,
                    bg=SIDEBAR,
                ).pack(pady=(70, 15))
            except Exception:
                self._login_symbol(left)
        else:
            self._login_symbol(left)

        tk.Label(
            left,
            text="SMTP COMMAND\nCENTER",
            bg=SIDEBAR,
            fg=TEXT,
            font=("Segoe UI", 27, "bold"),
            justify="left",
        ).pack(
            anchor="w",
            padx=50,
        )

        tk.Label(
            left,
            text="Secure desktop mail management",
            bg=SIDEBAR,
            fg=MUTED,
            font=("Segoe UI", 10),
        ).pack(
            anchor="w",
            padx=52,
            pady=8,
        )

        right = tk.Frame(container, bg=BG)
        right.pack(
            side="left",
            fill="both",
            expand=True,
            padx=55,
            pady=80,
        )

        tk.Label(
            right,
            text="Welcome back",
            bg=BG,
            fg=TEXT,
            font=("Segoe UI", 25, "bold"),
        ).pack(anchor="w")

        tk.Label(
            right,
            text="Sign in to continue",
            bg=BG,
            fg=MUTED,
            font=("Segoe UI", 10),
        ).pack(
            anchor="w",
            pady=(4, 25),
        )

        tk.Label(
            right,
            text="USERNAME",
            bg=BG,
            fg=MUTED,
            font=("Segoe UI", 9, "bold"),
        ).pack(anchor="w")

        username = self.make_entry(right)
        username.insert(0, "admin")

        tk.Label(
            right,
            text="PASSWORD",
            bg=BG,
            fg=MUTED,
            font=("Segoe UI", 9, "bold"),
        ).pack(
            anchor="w",
            pady=(15, 4),
        )

        password = self.make_entry(right, "*")

        message = tk.Label(
            right,
            text="",
            bg=BG,
            fg=RED,
            font=("Segoe UI", 9),
        )
        message.pack(
            anchor="w",
            pady=8,
        )

        def login():
            role = self.db.verify_user(
                username.get(),
                password.get(),
            )

            if role:
                self.current_user = (
                    username.get().strip(),
                    role,
                )

                self.db.log(
                    "INFO",
                    f"Login: {username.get().strip()}",
                )

                self.show_main()
            else:
                message.config(
                    text="Invalid username or password"
                )

        self.make_button(
            right,
            "LOGIN",
            login,
            BLUE,
        ).pack(
            fill="x",
            pady=10,
        )

        tk.Label(
            right,
            text="First run: admin / admin",
            bg=BG,
            fg=YELLOW,
            font=("Segoe UI", 8),
        ).pack(anchor="w")

    def _login_symbol(self, parent):
        tk.Label(
            parent,
            text="✦",
            bg=SIDEBAR,
            fg=CYAN,
            font=("Segoe UI", 58, "bold"),
        ).pack(pady=(85, 10))

    # ========================================================
    # MAIN SHELL
    # ========================================================

    def show_main(self):
        self.clear_window()

        self.root.geometry("1280x820")
        self.root.minsize(1050, 700)

        self.root.grid_columnconfigure(0, weight=0)
        self.root.grid_columnconfigure(1, weight=1)
        self.root.grid_rowconfigure(0, weight=1)

        sidebar = tk.Frame(
            self.root,
            bg=SIDEBAR,
            width=240,
        )

        sidebar.grid(
            row=0,
            column=0,
            sticky="ns",
        )

        sidebar.grid_propagate(False)

        # Logo / brand
        brand = tk.Frame(sidebar, bg=SIDEBAR)
        brand.pack(fill="x", padx=20, pady=(22, 25))

        if os.path.exists(LOGO_PATH):
            try:
                image = tk.PhotoImage(file=LOGO_PATH)
                self.sidebar_logo = image

                tk.Label(
                    brand,
                    image=image,
                    bg=SIDEBAR,
                ).pack(
                    side="left",
                    padx=(0, 8),
                )
            except Exception:
                pass

        tk.Label(
            brand,
            text="✦ SMTP",
            bg=SIDEBAR,
            fg=CYAN,
            font=("Segoe UI", 18, "bold"),
        ).pack(anchor="w")

        tk.Label(
            brand,
            text="COMMAND CENTER",
            bg=SIDEBAR,
            fg=MUTED,
            font=("Segoe UI", 8, "bold"),
        ).pack(anchor="w")

        nav_items = [
            ("⌂  Dashboard", self.dashboard),
            ("✉  Compose", self.compose),
            ("👤  Sender Profiles", self.profiles_page),
            ("📄  Templates", self.templates_page),
            ("👥  Recipient Groups", self.groups_page),
            ("◷  Drafts", self.drafts_page),
            ("◷  Send History", self.history_page),
            ("📋  Activity Logs", self.logs_page),
            ("⚙  Settings", self.settings_page),
            ("🔒  Security", self.security_page),
        ]

        for label, command in nav_items:
            tk.Button(
                sidebar,
                text=label,
                command=command,
                bg=SIDEBAR,
                fg=MUTED,
                activebackground=CARD2,
                activeforeground=TEXT,
                relief="flat",
                anchor="w",
                padx=20,
                pady=10,
                font=("Segoe UI", 9),
                cursor="hand2",
            ).pack(
                fill="x",
                padx=7,
                pady=1,
            )

        tk.Frame(
            sidebar,
            bg=SIDEBAR,
        ).pack(
            fill="both",
            expand=True,
        )

        tk.Label(
            sidebar,
            text=f"● ONLINE  |  {self.current_user[0]}",
            bg=SIDEBAR,
            fg=GREEN,
            font=("Segoe UI", 8, "bold"),
        ).pack(
            anchor="w",
            padx=20,
            pady=(0, 10),
        )

        self.make_button(
            sidebar,
            "LOGOUT",
            self.logout,
            RED,
        ).pack(
            fill="x",
            padx=17,
            pady=(0, 20),
        )

        main = tk.Frame(
            self.root,
            bg=BG,
        )

        main.grid(
            row=0,
            column=1,
            sticky="nsew",
        )

        main.grid_columnconfigure(0, weight=1)
        main.grid_rowconfigure(1, weight=1)

        self.page_title = tk.Label(
            main,
            text="Dashboard",
            bg=BG,
            fg=TEXT,
            font=("Segoe UI", 25, "bold"),
        )

        self.page_title.grid(
            row=0,
            column=0,
            sticky="w",
            padx=30,
            pady=(25, 0),
        )

        self.page_subtitle = tk.Label(
            main,
            text="",
            bg=BG,
            fg=MUTED,
            font=("Segoe UI", 10),
        )

        self.page_subtitle.grid(
            row=0,
            column=0,
            sticky="w",
            padx=30,
            pady=(60, 0),
        )

        self.content = tk.Frame(
            main,
            bg=BG,
        )

        self.content.grid(
            row=1,
            column=0,
            sticky="nsew",
            padx=30,
            pady=20,
        )

        self.dashboard()

    # ========================================================
    # DASHBOARD
    # ========================================================

    def dashboard(self):
        self.page_header(
            "Dashboard",
            "Overview of your local SMTP mail system",
        )
        self.make_button(self.content,"↻ REFRESH",self.dashboard,CYAN).pack(anchor="e",pady=(0,8))

        total, sent, failed, profiles = self.db.stats()

        stat_row = tk.Frame(
            self.content,
            bg=BG,
        )
        stat_row.pack(fill="x")

        stats = [
            ("TOTAL", total, BLUE),
            ("SENT", sent, GREEN),
            ("FAILED", failed, RED),
            ("SENDERS", profiles, PURPLE),
        ]

        for index, (label, value, color) in enumerate(stats):
            stat_row.columnconfigure(index, weight=1)

            card = self.make_card(stat_row)
            card.grid(
                row=0,
                column=index,
                sticky="ew",
                padx=5,
            )

            tk.Label(
                card,
                text=label,
                bg=CARD,
                fg=MUTED,
                font=("Segoe UI", 8, "bold"),
            ).pack(
                anchor="w",
                padx=18,
                pady=(15, 2),
            )

            tk.Label(
                card,
                text=str(value),
                bg=CARD,
                fg=color,
                font=("Segoe UI", 25, "bold"),
            ).pack(
                anchor="w",
                padx=18,
                pady=(0, 15),
            )

        lower = tk.Frame(
            self.content,
            bg=BG,
        )

        lower.pack(
            fill="both",
            expand=True,
            pady=18,
        )

        lower.columnconfigure(0, weight=2)
        lower.columnconfigure(1, weight=1)
        lower.rowconfigure(0, weight=1)

        activity = self.make_card(
            lower,
            "Recent Activity",
        )

        activity.grid(
            row=0,
            column=0,
            sticky="nsew",
            padx=(0, 8),
        )

        history = self.db.list_history()[:15]

        self.show_tree(
            activity,
            (
                "time",
                "sender",
                "recipient",
                "subject",
                "status",
            ),
            (
                "TIME",
                "FROM",
                "TO",
                "SUBJECT",
                "STATUS",
            ),
            [
                (
                    row[6],
                    row[1],
                    row[2],
                    row[3],
                    row[4],
                )
                for row in history
            ],
            [145, 150, 170, 190, 90],
        )

        actions = self.make_card(
            lower,
            "Quick Actions",
        )

        actions.grid(
            row=0,
            column=1,
            sticky="nsew",
            padx=(8, 0),
        )

        quick_actions = [
            ("✉  Compose Email", self.compose, BLUE),
            ("👤  Sender Profiles", self.profiles_page, PURPLE),
            ("🧪  SMTP Tester", self.profiles_page, CYAN),
            ("📄  Templates", self.templates_page, GREEN),
        ]

        for text, command, color in quick_actions:
            self.make_button(
                actions,
                text,
                command,
                color,
            ).pack(
                fill="x",
                padx=15,
                pady=7,
            )

    # ========================================================
    # COMPOSE
    # ========================================================

    def compose(self, selected_profile=None):
        self.page_header(
            "Compose Email",
            "Send a message through a saved sender profile",
        )

        profiles = self.db.list_profiles()
        profile_names = [row[1] for row in profiles]

        outer = self.make_card(self.content)
        outer.pack(
            fill="both",
            expand=True,
        )

        outer.grid_columnconfigure(1, weight=1)
        outer.grid_rowconfigure(5, weight=1)

        def label(text, row):
            tk.Label(
                outer,
                text=text,
                bg=CARD,
                fg=MUTED,
                font=("Segoe UI", 8, "bold"),
            ).grid(
                row=row,
                column=0,
                sticky="nw",
                padx=18,
                pady=8,
            )

        def field(row):
            entry = tk.Entry(
                outer,
                bg=ENTRY_BG,
                fg=TEXT,
                insertbackground=TEXT,
                relief="flat",
                font=("Segoe UI", 10),
            )

            entry.grid(
                row=row,
                column=1,
                sticky="ew",
                padx=18,
                pady=7,
                ipady=7,
            )

            return entry

        label("PROFILE", 0)

        profile_var = tk.StringVar(
            value=selected_profile or (
                profile_names[0]
                if profile_names
                else ""
            )
        )

        profile_combo = ttk.Combobox(
            outer,
            textvariable=profile_var,
            values=profile_names,
            state="readonly",
        )

        profile_combo.grid(
            row=0,
            column=1,
            sticky="ew",
            padx=18,
            pady=7,
        )

        label("TO", 1)
        to_entry = field(1)

        label("CC", 2)
        cc_entry = field(2)

        label("BCC", 3)
        bcc_entry = field(3)

        label("SUBJECT", 4)
        subject_entry = field(4)

        label("MESSAGE", 5)

        body = tk.Text(
            outer,
            bg=ENTRY_BG,
            fg=TEXT,
            insertbackground=TEXT,
            relief="flat",
            wrap="word",
            font=("Segoe UI", 10),
        )

        body.grid(
            row=5,
            column=1,
            sticky="nsew",
            padx=18,
            pady=7,
        )

        html_var = tk.BooleanVar(value=False)

        tk.Checkbutton(
            outer,
            text="HTML email",
            variable=html_var,
            bg=CARD,
            fg=TEXT,
            selectcolor=ENTRY_BG,
            activebackground=CARD,
            activeforeground=TEXT,
        ).grid(
            row=6,
            column=1,
            sticky="w",
            padx=18,
        )

        toolbar = tk.Frame(
            outer,
            bg=CARD,
        )

        toolbar.grid(
            row=7,
            column=0,
            columnspan=2,
            sticky="ew",
            padx=18,
            pady=15,
        )

        attachment_label = tk.Label(
            toolbar,
            text="No attachments",
            bg=CARD,
            fg=MUTED,
            font=("Segoe UI", 8),
        )

        attachment_label.pack(side="left")

        def add_attachments():
            files = filedialog.askopenfilenames(
                title="Select attachments",
            )

            if files:
                self.attachments = list(
                    dict.fromkeys(
                        self.attachments + list(files)
                    )
                )

                attachment_label.config(
                    text=", ".join(
                        os.path.basename(x)
                        for x in self.attachments
                    )
                )

        def clear_compose():
            self.attachments = []
            self.compose(selected_profile)

        def save_draft():
            self.save_draft_dialog(
                to_entry.get(),
                cc_entry.get(),
                bcc_entry.get(),
                subject_entry.get(),
                body.get("1.0", "end").strip(),
                html_var.get(),
            )

        self.make_button(
            toolbar,
            "+ ATTACH",
            add_attachments,
            CARD2,
        ).pack(side="right", padx=4)

        self.make_button(
            toolbar,
            "SAVE DRAFT",
            save_draft,
            PURPLE,
        ).pack(side="right", padx=4)

        self.make_button(
            toolbar,
            "SEND",
            lambda: self.queue_message(
                profile_var.get(),
                to_entry.get(),
                cc_entry.get(),
                bcc_entry.get(),
                subject_entry.get(),
                body.get("1.0", "end").strip(),
                html_var.get(),
            ),
            GREEN,
        ).pack(side="right", padx=4)

        self.make_button(
            toolbar,
            "CLEAR",
            clear_compose,
            CARD2,
        ).pack(side="right", padx=4)

        template_bar = tk.Frame(
            outer,
            bg=CARD,
        )

        template_bar.grid(
            row=8,
            column=0,
            columnspan=2,
            sticky="ew",
            padx=18,
            pady=(0, 12),
        )

        tk.Label(
            template_bar,
            text="LOAD TEMPLATE:",
            bg=CARD,
            fg=MUTED,
        ).pack(side="left")

        template_rows = self.db.list_templates()
        template_names = [x[1] for x in template_rows]

        template_var = tk.StringVar()

        template_combo = ttk.Combobox(
            template_bar,
            textvariable=template_var,
            values=template_names,
            state="readonly",
            width=28,
        )

        template_combo.pack(
            side="left",
            padx=8,
        )

        def load_template():
            selected = template_var.get()

            for row in template_rows:
                if row[1] == selected:
                    subject_entry.delete(0, "end")
                    subject_entry.insert(0, row[2] or "")

                    body.delete("1.0", "end")
                    body.insert("1.0", row[3] or "")
                    break

        self.make_button(
            template_bar,
            "LOAD",
            load_template,
            BLUE,
        ).pack(side="left")

        # Keep references
        self.compose_widgets = {
            "profile": profile_var,
            "to": to_entry,
            "cc": cc_entry,
            "bcc": bcc_entry,
            "subject": subject_entry,
            "body": body,
            "html": html_var,
        }

    def save_draft_dialog(
        self,
        recipient,
        cc,
        bcc,
        subject,
        body,
        html,
    ):
        dialog = tk.Toplevel(self.root)
        dialog.title("Save Draft")
        dialog.geometry("420x210")
        dialog.configure(bg=BG)
        dialog.transient(self.root)
        dialog.grab_set()

        tk.Label(
            dialog,
            text="DRAFT NAME",
            bg=BG,
            fg=MUTED,
        ).pack(
            anchor="w",
            padx=22,
            pady=(22, 5),
        )

        name_entry = self.make_entry(dialog)

        def save():
            name = name_entry.get().strip()

            if not name:
                messagebox.showwarning(
                    "Draft",
                    "Enter a draft name.",
                    parent=dialog,
                )
                return

            self.db.save_draft(
                name,
                recipient,
                cc,
                bcc,
                subject,
                body,
                html,
            )

            self.db.log(
                "INFO",
                f"Draft saved: {name}",
            )

            dialog.destroy()

            messagebox.showinfo(
                "Draft",
                "Draft saved successfully.",
            )

        self.make_button(
            dialog,
            "SAVE DRAFT",
            save,
            PURPLE,
        ).pack(
            fill="x",
            padx=22,
            pady=20,
        )

    # ========================================================
    # SEND QUEUE
    # ========================================================

    def queue_message(
        self,
        profile_name,
        recipient,
        cc,
        bcc,
        subject,
        body,
        html,
    ):
        if not profile_name:
            messagebox.showwarning(
                "Sender Profile",
                "Create/select a sender profile first.",
            )
            return

        profile = next(
            (
                row
                for row in self.db.list_profiles()
                if row[1] == profile_name
            ),
            None,
        )

        if not profile:
            messagebox.showerror(
                "Profile",
                "Selected profile was not found.",
            )
            return

        if not recipient.strip():
            messagebox.showwarning(
                "Recipient",
                "Enter at least one recipient.",
            )
            return

        if not subject.strip():
            messagebox.showwarning(
                "Subject",
                "Enter a subject.",
            )
            return

        if not body.strip():
            messagebox.showwarning(
                "Message",
                "Enter a message.",
            )
            return

        files = list(self.attachments)

        self.send_queue.put(
            (
                profile,
                recipient,
                cc,
                bcc,
                subject,
                body,
                html,
                files,
            )
        )

        self.attachments = []

        self.start_queue()

        messagebox.showinfo(
            "Send Queue",
            "Message added to the send queue.",
        )

    def start_queue(self):
        if self.queue_running:
            return

        self.queue_running = True

        thread = threading.Thread(
            target=self.queue_worker,
            daemon=True,
        )

        thread.start()

    def queue_worker(self):
        while True:
            try:
                item = self.send_queue.get_nowait()
            except queue.Empty:
                break

            try:
                self.send_message(item)
            except Exception as exc:
                self.db.log(
                    "ERROR",
                    f"Unexpected queue error: {exc}",
                )
            finally:
                self.send_queue.task_done()

        self.queue_running = False

    def send_message(self, item):
        (
            profile,
            recipient,
            cc,
            bcc,
            subject,
            body,
            html,
            attachments,
        ) = item

        (
            profile_id,
            profile_name,
            provider,
            server,
            port,
            security,
            username,
            sender,
            display_name,
            created,
        ) = profile

        password = get_smtp_password(
            profile_name,
            username,
        )

        if not password:
            error = (
                "SMTP credential not found in the OS keyring."
            )

            self.db.add_history(
                profile_name,
                sender,
                recipient,
                subject,
                "FAILED",
                error,
            )

            self.db.log(
                "ERROR",
                f"Send failed: {error}",
            )

            return

        message = EmailMessage()

        message["From"] = (
            formataddr(
                (display_name, sender)
            )
            if display_name
            else sender
        )

        message["To"] = recipient

        if cc.strip():
            message["Cc"] = cc

        if bcc.strip():
            message["Bcc"] = bcc

        message["Subject"] = subject

        if html:
            message.set_content(
                "This message contains HTML content."
            )
            message.add_alternative(
                body,
                subtype="html",
            )
        else:
            message.set_content(body)

        for file_path in attachments:
            if not os.path.isfile(file_path):
                continue

            with open(file_path, "rb") as file:
                data = file.read()

            mime_type, _ = mimetypes.guess_type(
                file_path
            )

            if mime_type:
                maintype, subtype = mime_type.split(
                    "/",
                    1,
                )
            else:
                maintype = "application"
                subtype = "octet-stream"

            message.add_attachment(
                data,
                maintype=maintype,
                subtype=subtype,
                filename=os.path.basename(file_path),
            )

        context = ssl.create_default_context()
        smtp = None

        try:
            if security.upper() == "SSL":
                smtp = smtplib.SMTP_SSL(
                    server,
                    int(port),
                    timeout=30,
                    context=context,
                )
            else:
                smtp = smtplib.SMTP(
                    server,
                    int(port),
                    timeout=30,
                )

                smtp.ehlo()
                smtp.starttls(context=context)
                smtp.ehlo()

            smtp.login(
                username,
                password,
            )

            smtp.send_message(message)

            self.db.add_history(
                profile_name,
                sender,
                recipient,
                subject,
                "SENT",
            )

            self.db.log(
                "SUCCESS",
                f"Email sent via {profile_name} to {recipient}",
            )

        except Exception as exc:
            self.db.add_history(
                profile_name,
                sender,
                recipient,
                subject,
                "FAILED",
                str(exc),
            )

            self.db.log(
                "ERROR",
                f"Email failed via {profile_name}: {exc}",
            )

        finally:
            if smtp is not None:
                try:
                    smtp.quit()
                except Exception:
                    pass

    # ========================================================
    # SENDER PROFILES
    # ========================================================

    def profiles_page(self):
        self.page_header(
            "Sender Profiles",
            "Saved SMTP accounts and connection testing",
        )

        toolbar = tk.Frame(
            self.content,
            bg=BG,
        )
        toolbar.pack(
            fill="x",
            pady=(0, 10),
        )

        self.make_button(toolbar, "↻ REFRESH", self.profiles_page, CYAN).pack(side="right", padx=(8,0))
        self.make_button(
            toolbar, "+ ADD SENDER", self.add_profile, BLUE,
        ).pack(side="right")

        profiles = self.db.list_profiles()

        if not profiles:
            empty = self.make_card(self.content)
            empty.pack(fill="x", pady=10)

            tk.Label(
                empty,
                text="No sender profiles yet.",
                bg=CARD,
                fg=MUTED,
                font=("Segoe UI", 11),
            ).pack(pady=30)

            return

        for profile in profiles:
            self.profile_card(profile)

    def profile_card(self, profile):
        (
            profile_id,
            name,
            provider,
            server,
            port,
            security,
            username,
            sender,
            display_name,
            created,
        ) = profile

        card = self.make_card(self.content)
        card.pack(
            fill="x",
            pady=5,
        )

        left = tk.Frame(
            card,
            bg=CARD,
        )

        left.pack(
            side="left",
            fill="both",
            expand=True,
            padx=18,
            pady=14,
        )

        tk.Label(
            left,
            text=f"✉  {name}",
            bg=CARD,
            fg=TEXT,
            font=("Segoe UI", 12, "bold"),
        ).pack(anchor="w")

        tk.Label(
            left,
            text=f"{sender}  •  {provider}",
            bg=CARD,
            fg=MUTED,
        ).pack(
            anchor="w",
            pady=3,
        )

        tk.Label(
            left,
            text=f"{server}:{port}  •  {security}",
            bg=CARD,
            fg=CYAN,
        ).pack(anchor="w")

        actions = tk.Frame(
            card,
            bg=CARD,
        )

        actions.pack(
            side="right",
            padx=15,
        )

        self.make_button(actions, "EDIT", lambda p=profile: self.edit_profile(p), PURPLE).pack(side="left", padx=3)

        self.make_button(
            actions,
            "TEST",
            lambda p=profile: self.test_profile(p),
            CYAN,
        ).pack(
            side="left",
            padx=3,
        )

        self.make_button(
            actions,
            "USE",
            lambda n=name: self.compose(n),
            BLUE,
        ).pack(
            side="left",
            padx=3,
        )

        self.make_button(
            actions,
            "DELETE",
            lambda p=profile: self.delete_profile(p),
            RED,
        ).pack(
            side="left",
            padx=3,
        )

    def add_profile(self):
        dialog = tk.Toplevel(self.root)
        dialog.title("Add Sender Profile")
        dialog.geometry("600x720")
        dialog.configure(bg=BG)
        dialog.transient(self.root)
        dialog.grab_set()

        frame = tk.Frame(
            dialog,
            bg=BG,
        )

        frame.pack(
            fill="both",
            expand=True,
            padx=25,
            pady=20,
        )

        fields = {}

        def labeled_entry(label, key, password=False):
            tk.Label(
                frame,
                text=label,
                bg=BG,
                fg=MUTED,
                font=("Segoe UI", 8, "bold"),
            ).pack(
                anchor="w",
                pady=(8, 3),
            )

            fields[key] = self.make_entry(
                frame,
                "*" if password else None,
            )

        labeled_entry("PROFILE NAME", "name")

        tk.Label(
            frame,
            text="PROVIDER",
            bg=BG,
            fg=MUTED,
            font=("Segoe UI", 8, "bold"),
        ).pack(
            anchor="w",
            pady=(8, 3),
        )

        provider_var = tk.StringVar(
            value=list(PROVIDERS.keys())[0]
        )

        provider_combo = ttk.Combobox(
            frame,
            textvariable=provider_var,
            values=list(PROVIDERS.keys()),
            state="readonly",
        )

        provider_combo.pack(
            fill="x",
            ipady=5,
        )

        labeled_entry("SMTP SERVER", "server")

        port_security = tk.Frame(
            frame,
            bg=BG,
        )

        port_security.pack(
            fill="x",
            pady=5,
        )

        port_security.columnconfigure(
            0,
            weight=1,
        )

        port_security.columnconfigure(
            1,
            weight=1,
        )

        tk.Label(
            port_security,
            text="PORT",
            bg=BG,
            fg=MUTED,
            font=("Segoe UI", 8, "bold"),
        ).grid(
            row=0,
            column=0,
            sticky="w",
        )

        tk.Label(
            port_security,
            text="SECURITY",
            bg=BG,
            fg=MUTED,
            font=("Segoe UI", 8, "bold"),
        ).grid(
            row=0,
            column=1,
            sticky="w",
            padx=(15, 0),
        )

        port_entry = tk.Entry(
            port_security,
            bg=ENTRY_BG,
            fg=TEXT,
            insertbackground=TEXT,
            relief="flat",
        )

        port_entry.grid(
            row=1,
            column=0,
            sticky="ew",
            ipady=8,
        )

        security_var = tk.StringVar(
            value="STARTTLS"
        )

        security_combo = ttk.Combobox(
            port_security,
            textvariable=security_var,
            values=["SSL", "STARTTLS"],
            state="readonly",
        )

        security_combo.grid(
            row=1,
            column=1,
            sticky="ew",
            padx=(15, 0),
            ipady=5,
        )

        labeled_entry(
            "USERNAME / EMAIL",
            "username",
        )

        labeled_entry(
            "FROM ADDRESS",
            "sender",
        )

        labeled_entry(
            "DISPLAY NAME",
            "display_name",
        )

        labeled_entry(
            "PASSWORD / APP PASSWORD",
            "password",
            True,
        )

        def apply_provider_defaults(event=None):
            options = PROVIDERS.get(
                provider_var.get(),
                [],
            )

            if not options:
                return

            server, port, security = options[0]

            fields["server"].delete(0, "end")
            fields["server"].insert(0, server)

            port_entry.delete(0, "end")
            port_entry.insert(0, str(port))

            security_var.set(security)

        provider_combo.bind(
            "<<ComboboxSelected>>",
            apply_provider_defaults,
        )

        apply_provider_defaults()

        def save_profile():
            name = fields["name"].get().strip()
            provider = provider_var.get()
            server = fields["server"].get().strip()
            port = port_entry.get().strip()
            security = security_var.get()
            username = fields["username"].get().strip()
            sender = fields["sender"].get().strip()
            display_name = fields["display_name"].get().strip()
            password = fields["password"].get()

            if not all(
                [
                    name,
                    provider,
                    server,
                    port,
                    username,
                    sender,
                    password,
                ]
            ):
                messagebox.showerror(
                    "Validation",
                    "Complete all required fields.",
                    parent=dialog,
                )
                return

            try:
                port_number = int(port)

                if not 1 <= port_number <= 65535:
                    raise ValueError(
                        "Port must be between 1 and 65535."
                    )

                self.db.add_profile(
                    name,
                    provider,
                    server,
                    port_number,
                    security,
                    username,
                    sender,
                    display_name,
                )

                save_smtp_password(
                    name,
                    username,
                    password,
                )

                self.db.log(
                    "INFO",
                    f"Sender profile added: {name}",
                )

                dialog.destroy()
                self.profiles_page()

            except sqlite3.IntegrityError:
                messagebox.showerror(
                    "Profile",
                    "A profile with this name already exists.",
                    parent=dialog,
                )

            except Exception as exc:
                messagebox.showerror(
                    "Error",
                    str(exc),
                    parent=dialog,
                )

        self.make_button(
            frame,
            "SAVE PROFILE",
            save_profile,
            GREEN,
        ).pack(
            fill="x",
            pady=20,
        )

    def edit_profile(self, profile):
        (pid, old_name, old_provider, old_server, old_port, old_security,
         old_username, old_sender, old_display, created) = profile
        dialog = tk.Toplevel(self.root); dialog.title("Edit Sender Profile"); dialog.geometry("600x720")
        dialog.configure(bg=BG); dialog.transient(self.root); dialog.grab_set()
        frame = tk.Frame(dialog, bg=BG); frame.pack(fill="both", expand=True, padx=25, pady=20)
        fields = {}
        def field(label, key, value="", secret=False):
            tk.Label(frame, text=label, bg=BG, fg=MUTED, font=("Segoe UI",8,"bold")).pack(anchor="w", pady=(8,3))
            e=self.make_entry(frame, "*" if secret else None); e.insert(0, value or ""); fields[key]=e
        field("PROFILE NAME","name",old_name)
        tk.Label(frame,text="PROVIDER",bg=BG,fg=MUTED,font=("Segoe UI",8,"bold")).pack(anchor="w",pady=(8,3))
        pv=tk.StringVar(value=old_provider); pc=ttk.Combobox(frame,textvariable=pv,values=list(PROVIDERS.keys()),state="readonly"); pc.pack(fill="x",ipady=5)
        field("SMTP SERVER","server",old_server)
        row=tk.Frame(frame,bg=BG); row.pack(fill="x",pady=5); row.columnconfigure(0,weight=1); row.columnconfigure(1,weight=1)
        tk.Label(row,text="PORT",bg=BG,fg=MUTED).grid(row=0,column=0,sticky="w"); tk.Label(row,text="SECURITY",bg=BG,fg=MUTED).grid(row=0,column=1,sticky="w",padx=(15,0))
        port=tk.Entry(row,bg=ENTRY_BG,fg=TEXT,insertbackground=TEXT,relief="flat"); port.grid(row=1,column=0,sticky="ew",ipady=8); port.insert(0,str(old_port))
        secv=tk.StringVar(value=old_security); sec=ttk.Combobox(row,textvariable=secv,values=["SSL","STARTTLS"],state="readonly"); sec.grid(row=1,column=1,sticky="ew",padx=(15,0),ipady=5)
        field("USERNAME / EMAIL","username",old_username); field("FROM ADDRESS","sender",old_sender); field("DISPLAY NAME","display_name",old_display)
        field("NEW PASSWORD / APP PASSWORD (blank = keep current)","password","",True)
        def save():
            name=fields["name"].get().strip(); server=fields["server"].get().strip(); porttxt=port.get().strip(); user=fields["username"].get().strip(); sender=fields["sender"].get().strip(); display=fields["display_name"].get().strip(); newpw=fields["password"].get()
            if not all([name,pv.get(),server,porttxt,user,sender]): return messagebox.showerror("Validation","Complete all required fields.",parent=dialog)
            try:
                portno=int(porttxt)
                if not 1 <= portno <= 65535: raise ValueError("Port must be between 1 and 65535.")
                pw=newpw or get_smtp_password(old_name,old_username)
                if not pw: raise ValueError("SMTP password/app password is missing. Enter it before saving.")
                if (old_name,old_username)!=(name,user): delete_smtp_password(old_name,old_username)
                self.db.update_profile(pid,name,pv.get(),server,portno,secv.get(),user,sender,display)
                save_smtp_password(name,user,pw); self.db.log("INFO",f"Sender profile updated: {name}")
                dialog.destroy(); self.profiles_page()
            except sqlite3.IntegrityError: messagebox.showerror("Profile","A profile with this name already exists.",parent=dialog)
            except Exception as exc: messagebox.showerror("Error",str(exc),parent=dialog)
        self.make_button(frame,"SAVE CHANGES",save,GREEN).pack(fill="x",pady=20)

    def delete_profile(self, profile):
        profile_id = profile[0]
        name = profile[1]
        username = profile[6]

        if not messagebox.askyesno(
            "Delete Profile",
            f"Delete sender profile '{name}'?",
        ):
            return

        delete_smtp_password(
            name,
            username,
        )

        self.db.delete_profile(profile_id)

        self.db.log(
            "INFO",
            f"Sender profile deleted: {name}",
        )

        self.profiles_page()

    def test_profile(self, profile):
        (
            profile_id,
            name,
            provider,
            server,
            port,
            security,
            username,
            sender,
            display_name,
            created,
        ) = profile

        password = get_smtp_password(
            name,
            username,
        )

        if not password:
            messagebox.showerror(
                "Credentials",
                "Saved SMTP credential was not found.",
            )
            return

        smtp = None

        try:
            context = ssl.create_default_context()

            if security.upper() == "SSL":
                smtp = smtplib.SMTP_SSL(
                    server,
                    int(port),
                    timeout=20,
                    context=context,
                )
            else:
                smtp = smtplib.SMTP(
                    server,
                    int(port),
                    timeout=20,
                )

                smtp.ehlo()
                smtp.starttls(
                    context=context,
                )
                smtp.ehlo()

            smtp.login(
                username,
                password,
            )

            self.db.log(
                "SUCCESS",
                f"SMTP test passed: {name}",
            )

            messagebox.showinfo(
                "SMTP Test",
                "Connection and authentication successful.",
            )

        except Exception as exc:
            self.db.log(
                "ERROR",
                f"SMTP test failed: {name}: {exc}",
            )

            messagebox.showerror(
                "SMTP Test Failed",
                f"{type(exc).__name__}\n\n{exc}",
            )

        finally:
            if smtp is not None:
                try:
                    smtp.quit()
                except Exception:
                    pass

    # ========================================================
    # TEMPLATES
    # ========================================================

    def templates_page(self):
        self.page_header(
            "Email Templates",
            "Reusable message templates",
        )

        toolbar = tk.Frame(
            self.content,
            bg=BG,
        )

        toolbar.pack(
            fill="x",
            pady=(0, 10),
        )

        self.make_button(toolbar,"↻ REFRESH",self.templates_page,CYAN).pack(side="right",padx=(8,0))
        self.make_button(toolbar,"+ NEW TEMPLATE",self.add_template,BLUE).pack(side="right")

        templates = self.db.list_templates()

        if not templates:
            card = self.make_card(self.content)
            card.pack(fill="x")

            tk.Label(
                card,
                text="No templates created yet.",
                bg=CARD,
                fg=MUTED,
            ).pack(pady=30)

            return

        for template in templates:
            template_id, name, subject, body, created = template

            card = self.make_card(self.content)
            card.pack(
                fill="x",
                pady=5,
            )

            tk.Label(
                card,
                text=name,
                bg=CARD,
                fg=TEXT,
                font=("Segoe UI", 11, "bold"),
            ).pack(
                side="left",
                padx=18,
                pady=14,
            )

            tk.Label(
                card,
                text=subject or "",
                bg=CARD,
                fg=MUTED,
            ).pack(
                side="left",
                padx=10,
            )

            self.make_button(card,"EDIT",lambda t=template:self.edit_template(t),PURPLE).pack(side="right",padx=3,pady=8)
            self.make_button(card,"DELETE",lambda i=template_id:self.delete_template(i),RED).pack(side="right",padx=15,pady=8)

    def add_template(self):
        dialog = tk.Toplevel(self.root)
        dialog.title("New Template")
        dialog.geometry("700x560")
        dialog.configure(bg=BG)
        dialog.transient(self.root)
        dialog.grab_set()

        frame = tk.Frame(
            dialog,
            bg=BG,
        )

        frame.pack(
            fill="both",
            expand=True,
            padx=25,
            pady=20,
        )

        tk.Label(
            frame,
            text="NAME",
            bg=BG,
            fg=MUTED,
        ).pack(anchor="w")

        name = self.make_entry(frame)

        tk.Label(
            frame,
            text="SUBJECT",
            bg=BG,
            fg=MUTED,
        ).pack(
            anchor="w",
            pady=(15, 4),
        )

        subject = self.make_entry(frame)

        tk.Label(
            frame,
            text="BODY",
            bg=BG,
            fg=MUTED,
        ).pack(
            anchor="w",
            pady=(15, 4),
        )

        body = tk.Text(
            frame,
            bg=ENTRY_BG,
            fg=TEXT,
            insertbackground=TEXT,
            relief="flat",
            wrap="word",
        )

        body.pack(
            fill="both",
            expand=True,
        )

        def save():
            if not name.get().strip():
                messagebox.showwarning(
                    "Template",
                    "Enter a template name.",
                    parent=dialog,
                )
                return

            self.db.save_template(
                name.get().strip(),
                subject.get(),
                body.get("1.0", "end").strip(),
            )

            self.db.log(
                "INFO",
                f"Template saved: {name.get().strip()}",
            )

            dialog.destroy()
            self.templates_page()

        self.make_button(
            frame,
            "SAVE TEMPLATE",
            save,
            GREEN,
        ).pack(
            fill="x",
            pady=12,
        )

    def delete_template(self, template_id):
        if messagebox.askyesno(
            "Delete Template",
            "Delete this template?",
        ):
            self.db.delete_template(template_id)
            self.templates_page()

    # ========================================================
    # DRAFTS
    # ========================================================

    def drafts_page(self):
        self.page_header(
            "Drafts",
            "Saved email drafts",
        )

        self.make_button(self.content,"↻ REFRESH",self.drafts_page,CYAN).pack(anchor="e",pady=(0,8))

        drafts = self.db.list_drafts()

        if not drafts:
            card = self.make_card(self.content)
            card.pack(fill="x")

            tk.Label(
                card,
                text="No drafts saved.",
                bg=CARD,
                fg=MUTED,
            ).pack(pady=30)

            return

        for draft in drafts:
            (
                draft_id,
                name,
                recipient,
                cc,
                bcc,
                subject,
                body,
                html,
                updated,
            ) = draft

            card = self.make_card(self.content)
            card.pack(
                fill="x",
                pady=5,
            )

            info = tk.Frame(
                card,
                bg=CARD,
            )

            info.pack(
                side="left",
                fill="both",
                expand=True,
                padx=18,
                pady=12,
            )

            tk.Label(
                info,
                text=name,
                bg=CARD,
                fg=TEXT,
                font=("Segoe UI", 11, "bold"),
            ).pack(anchor="w")

            tk.Label(
                info,
                text=f"{subject}  •  {updated}",
                bg=CARD,
                fg=MUTED,
            ).pack(anchor="w")

            actions = tk.Frame(
                card,
                bg=CARD,
            )

            actions.pack(
                side="right",
                padx=15,
            )

            self.make_button(
                actions,
                "OPEN",
                lambda d=draft: self.open_draft(d),
                BLUE,
            ).pack(
                side="left",
                padx=3,
            )

            self.make_button(
                actions,
                "DELETE",
                lambda i=draft_id: self.delete_draft(i),
                RED,
            ).pack(
                side="left",
                padx=3,
            )

    def open_draft(self, draft):
        (
            draft_id,
            name,
            recipient,
            cc,
            bcc,
            subject,
            body,
            html,
            updated,
        ) = draft

        profiles = self.db.list_profiles()

        self.compose()

        widgets = self.compose_widgets

        if profiles:
            widgets["profile"].set(
                profiles[0][1]
            )

        widgets["to"].insert(
            0,
            recipient or "",
        )

        widgets["cc"].insert(
            0,
            cc or "",
        )

        widgets["bcc"].insert(
            0,
            bcc or "",
        )

        widgets["subject"].insert(
            0,
            subject or "",
        )

        widgets["body"].insert(
            "1.0",
            body or "",
        )

        widgets["html"].set(
            bool(html)
        )

    def delete_draft(self, draft_id):
        if messagebox.askyesno(
            "Delete Draft",
            "Delete this draft?",
        ):
            self.db.delete_draft(draft_id)
            self.drafts_page()

    # ========================================================
    # RECIPIENT GROUPS
    # ========================================================

    def groups_page(self):
        self.page_header(
            "Recipient Groups",
            "Manage recipient groups for contacts you are authorized to email",
        )

        toolbar = tk.Frame(
            self.content,
            bg=BG,
        )

        toolbar.pack(
            fill="x",
            pady=(0, 10),
        )

        self.make_button(toolbar,"↻ REFRESH",self.groups_page,CYAN).pack(side="right",padx=(8,0))
        self.make_button(toolbar,"+ NEW GROUP",self.add_group,BLUE).pack(side="right")

        groups = self.db.list_groups()

        if not groups:
            card = self.make_card(self.content)
            card.pack(fill="x")

            tk.Label(
                card,
                text="No recipient groups created.",
                bg=CARD,
                fg=MUTED,
            ).pack(pady=30)

            return

        for group in groups:
            group_id, name, recipients, created = group

            card = self.make_card(self.content)
            card.pack(
                fill="x",
                pady=5,
            )

            tk.Label(
                card,
                text=name,
                bg=CARD,
                fg=TEXT,
                font=("Segoe UI", 11, "bold"),
            ).pack(
                side="left",
                padx=18,
                pady=14,
            )

            count = len(
                self.parse_recipients(recipients)
            )

            tk.Label(
                card,
                text=f"{count} recipients",
                bg=CARD,
                fg=MUTED,
            ).pack(side="left")

            self.make_button(card,"EDIT",lambda g=group:self.edit_group(g),PURPLE).pack(side="right",padx=3,pady=8)
            self.make_button(card,"DELETE",lambda i=group_id:self.delete_group(i),RED).pack(side="right",padx=15,pady=8)

    @staticmethod
    def parse_recipients(value):
        value = value.replace(";", ",")
        return [
            item.strip()
            for item in value.split(",")
            if item.strip()
        ]

    def add_group(self):
        dialog = tk.Toplevel(self.root)
        dialog.title("New Recipient Group")
        dialog.geometry("700x520")
        dialog.configure(bg=BG)
        dialog.transient(self.root)
        dialog.grab_set()

        frame = tk.Frame(
            dialog,
            bg=BG,
        )

        frame.pack(
            fill="both",
            expand=True,
            padx=25,
            pady=20,
        )

        tk.Label(
            frame,
            text="GROUP NAME",
            bg=BG,
            fg=MUTED,
        ).pack(anchor="w")

        name = self.make_entry(frame)

        tk.Label(
            frame,
            text="RECIPIENTS — comma separated",
            bg=BG,
            fg=MUTED,
        ).pack(
            anchor="w",
            pady=(15, 4),
        )

        recipients = tk.Text(
            frame,
            bg=ENTRY_BG,
            fg=TEXT,
            insertbackground=TEXT,
            relief="flat",
            wrap="word",
        )

        recipients.pack(
            fill="both",
            expand=True,
        )

        def save():
            group_name = name.get().strip()
            emails = self.parse_recipients(
                recipients.get("1.0", "end")
            )

            if not group_name or not emails:
                messagebox.showwarning(
                    "Group",
                    "Enter a name and at least one recipient.",
                    parent=dialog,
                )
                return

            self.db.save_group(
                group_name,
                ",".join(emails),
            )

            self.db.log(
                "INFO",
                f"Recipient group saved: {group_name}",
            )

            dialog.destroy()
            self.groups_page()

        self.make_button(
            frame,
            "SAVE GROUP",
            save,
            GREEN,
        ).pack(
            fill="x",
            pady=12,
        )

    def delete_group(self, group_id):
        if messagebox.askyesno(
            "Delete Group",
            "Delete this recipient group?",
        ):
            self.db.delete_group(group_id)
            self.groups_page()

    # ========================================================
    # HISTORY
    # ========================================================

    def history_page(self):
        self.page_header(
            "Send History",
            "Sent and failed messages",
        )
        self.make_button(self.content,"↻ REFRESH",self.history_page,CYAN).pack(anchor="e",pady=(0,8))

        card = self.make_card(self.content)
        card.pack(
            fill="both",
            expand=True,
        )

        rows = self.db.list_history()

        self.show_tree(
            card,
            (
                "profile",
                "sender",
                "recipient",
                "subject",
                "status",
                "error",
                "time",
            ),
            (
                "PROFILE",
                "FROM",
                "TO",
                "SUBJECT",
                "STATUS",
                "ERROR",
                "TIME",
            ),
            rows,
            [120, 150, 170, 190, 90, 220, 150],
        )

        self.make_button(
            self.content,
            "EXPORT CSV",
            self.export_history_csv,
            BLUE,
        ).pack(
            anchor="e",
            pady=8,
        )

    def export_history_csv(self):
        path = filedialog.asksaveasfilename(
            title="Export history",
            defaultextension=".csv",
            filetypes=[
                ("CSV file", "*.csv"),
            ],
        )

        if not path:
            return

        rows = self.db.list_history()

        try:
            with open(
                path,
                "w",
                newline="",
                encoding="utf-8",
            ) as file:
                writer = csv.writer(file)

                writer.writerow(
                    [
                        "Profile",
                        "From",
                        "To",
                        "Subject",
                        "Status",
                        "Error",
                        "Time",
                    ]
                )

                writer.writerows(rows)

            self.db.log(
                "INFO",
                f"History exported: {path}",
            )

            messagebox.showinfo(
                "Export",
                "History exported successfully.",
            )

        except Exception as exc:
            messagebox.showerror(
                "Export",
                str(exc),
            )

    # ========================================================
    # LOGS
    # ========================================================

    def logs_page(self):
        self.page_header(
            "Activity Logs",
            "Application events and diagnostics",
        )
        self.make_button(self.content,"↻ REFRESH",self.logs_page,CYAN).pack(anchor="e",pady=(0,8))

        card = self.make_card(self.content)
        card.pack(
            fill="both",
            expand=True,
        )

        self.show_tree(
            card,
            (
                "level",
                "message",
                "time",
            ),
            (
                "LEVEL",
                "MESSAGE",
                "TIME",
            ),
            self.db.list_logs(),
            [100, 650, 180],
        )

    # ========================================================
    # SETTINGS
    # ========================================================

    def settings_page(self):
        self.page_header(
            "Settings",
            "SMTP provider presets, branding and application information",
        )
        self.make_button(self.content,"↻ REFRESH",self.settings_page,CYAN).pack(anchor="e",pady=(0,8))

        provider_card = self.make_card(
            self.content,
            "SMTP Provider Presets",
        )

        provider_card.pack(
            fill="both",
            expand=True,
        )

        rows = []

        for provider, options in PROVIDERS.items():
            for server, port, security in options:
                rows.append(
                    (
                        provider,
                        server,
                        port,
                        security,
                    )
                )

        self.show_tree(
            provider_card,
            (
                "provider",
                "server",
                "port",
                "security",
            ),
            (
                "PROVIDER",
                "SERVER",
                "PORT",
                "SECURITY",
            ),
            rows,
            [220, 260, 90, 110],
        )

        branding = self.make_card(
            self.content,
            "Branding",
        )

        branding.pack(
            fill="x",
            pady=12,
        )

        logo_status = (
            "Custom logo detected"
            if os.path.exists(LOGO_PATH)
            else "No logo.png found"
        )

        tk.Label(
            branding,
            text=(
                f"{logo_status}\n\n"
                f"Logo path: {LOGO_PATH}\n"
                "Place a PNG named 'logo.png' beside this script "
                "to use custom branding."
            ),
            bg=CARD,
            fg=MUTED,
            justify="left",
        ).pack(
            anchor="w",
            padx=18,
            pady=15,
        )

        system = self.make_card(
            self.content,
            "System",
        )

        system.pack(
            fill="x",
        )

        keyring_status = (
            "Available"
            if KEYRING_AVAILABLE
            else "Not installed"
        )

        tk.Label(
            system,
            text=f"OS credential storage: {keyring_status}",
            bg=CARD,
            fg=GREEN if KEYRING_AVAILABLE else YELLOW,
        ).pack(
            anchor="w",
            padx=18,
            pady=15,
        )

    # ========================================================
    # SECURITY
    # ========================================================

    def security_page(self):
        self.page_header(
            "Security",
            "Local authentication and credential protection",
        )
        self.make_button(self.content,"↻ REFRESH",self.security_page,CYAN).pack(anchor="e",pady=(0,8))

        card = self.make_card(
            self.content,
            "Security Center",
        )

        card.pack(
            fill="both",
            expand=True,
        )

        checks = [
            "✓ User passwords stored as salted PBKDF2 hashes",
            "✓ SMTP passwords kept outside SQLite",
            "✓ SMTP passwords stored through the OS keyring",
            "✓ SMTP connections support SSL / STARTTLS",
            "✓ Local application requires login",
        ]

        for text in checks:
            tk.Label(
                card,
                text=text,
                bg=CARD,
                fg=GREEN,
                font=("Segoe UI", 10),
            ).pack(
                anchor="w",
                padx=25,
                pady=7,
            )

        self.make_button(
            card,
            "CHANGE MY PASSWORD",
            self.change_my_password,
            PURPLE,
        ).pack(
            anchor="w",
            padx=20,
            pady=20,
        )

        if self.current_user[1] == "admin":
            self.make_button(
                card,
                "USER MANAGEMENT",
                self.user_management,
                BLUE,
            ).pack(
                anchor="w",
                padx=20,
            )

    def change_my_password(self):
        dialog = tk.Toplevel(self.root)
        dialog.title("Change Password")
        dialog.geometry("420x350")
        dialog.configure(bg=BG)
        dialog.transient(self.root)
        dialog.grab_set()

        frame = tk.Frame(
            dialog,
            bg=BG,
        )

        frame.pack(
            fill="both",
            expand=True,
            padx=25,
            pady=20,
        )

        tk.Label(
            frame,
            text="CURRENT PASSWORD",
            bg=BG,
            fg=MUTED,
        ).pack(anchor="w")

        current = self.make_entry(
            frame,
            "*",
        )

        tk.Label(
            frame,
            text="NEW PASSWORD",
            bg=BG,
            fg=MUTED,
        ).pack(
            anchor="w",
            pady=(15, 3),
        )

        new = self.make_entry(
            frame,
            "*",
        )

        tk.Label(
            frame,
            text="CONFIRM NEW PASSWORD",
            bg=BG,
            fg=MUTED,
        ).pack(
            anchor="w",
            pady=(15, 3),
        )

        confirm = self.make_entry(
            frame,
            "*",
        )

        def save():
            username = self.current_user[0]

            if not self.db.verify_user(
                username,
                current.get(),
            ):
                messagebox.showerror(
                    "Password",
                    "Current password is incorrect.",
                    parent=dialog,
                )
                return

            if len(new.get()) < 8:
                messagebox.showerror(
                    "Password",
                    "New password must be at least 8 characters.",
                    parent=dialog,
                )
                return

            if new.get() != confirm.get():
                messagebox.showerror(
                    "Password",
                    "New passwords do not match.",
                    parent=dialog,
                )
                return

            self.db.change_password(
                username,
                new.get(),
            )

            self.db.log(
                "INFO",
                f"Password changed for {username}",
            )

            dialog.destroy()

            messagebox.showinfo(
                "Security",
                "Password changed successfully.",
            )

        self.make_button(
            frame,
            "CHANGE PASSWORD",
            save,
            GREEN,
        ).pack(
            fill="x",
            pady=20,
        )

    # ========================================================
    # USER MANAGEMENT
    # ========================================================

    def user_management(self):
        dialog = tk.Toplevel(self.root)
        dialog.title("User Management")
        dialog.geometry("720x650")
        dialog.configure(bg=BG)
        dialog.transient(self.root)

        frame = tk.Frame(
            dialog,
            bg=BG,
        )

        frame.pack(
            fill="both",
            expand=True,
            padx=20,
            pady=20,
        )

        tk.Label(
            frame,
            text="LOCAL USERS",
            bg=BG,
            fg=TEXT,
            font=("Segoe UI", 14, "bold"),
        ).pack(
            anchor="w",
        )

        table_card = self.make_card(frame)
        table_card.pack(
            fill="both",
            expand=True,
            pady=12,
        )

        tree = self.show_tree(
            table_card,
            (
                "id",
                "username",
                "role",
                "created",
            ),
            (
                "ID",
                "USERNAME",
                "ROLE",
                "CREATED",
            ),
            self.db.list_users(),
            [60, 180, 100, 220],
        )

        create_card = self.make_card(
            frame,
            "Create User",
        )

        create_card.pack(
            fill="x",
        )

        username = self.make_entry(create_card)

        password = self.make_entry(
            create_card,
            "*",
        )

        def create():
            try:
                self.db.create_user(
                    username.get(),
                    password.get(),
                    "user",
                )

                self.db.log(
                    "INFO",
                    f"User created: {username.get().strip()}",
                )

                messagebox.showinfo(
                    "User",
                    "User created successfully.",
                    parent=dialog,
                )

                dialog.destroy()
                self.user_management()

            except Exception as exc:
                messagebox.showerror(
                    "User",
                    str(exc),
                    parent=dialog,
                )

        self.make_button(
            create_card,
            "CREATE USER",
            create,
            GREEN,
        ).pack(
            fill="x",
            padx=15,
            pady=15,
        )

    # ========================================================
    # LOGOUT / CLOSE
    # ========================================================

    def logout(self):
        if self.current_user:
            self.db.log(
                "INFO",
                f"Logout: {self.current_user[0]}",
            )

        self.current_user = None
        self.attachments = []

        self.show_login()

    def close_app(self):
        try:
            self.db.log(
                "INFO",
                "Application closed",
            )
        except Exception:
            pass

        self.root.destroy()


# ============================================================
# MAIN
# ============================================================

def main():
    root = tk.Tk()

    root.title(APP_NAME)

    # Linux/Windows friendly initial icon attempt
    try:
        if os.path.exists(LOGO_PATH):
            root.iconphoto(
                True,
                tk.PhotoImage(file=LOGO_PATH),
            )
    except Exception:
        pass

    SMTPCommandCenter(root)

    root.mainloop()


if __name__ == "__main__":
    main()
