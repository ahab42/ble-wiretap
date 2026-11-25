import json
import sqlite3
import threading
import time
from pathlib import Path

import frida

DB_PATH = Path("ble_wiretap.sqlite3")


def open_db(path: Path = DB_PATH) -> sqlite3.Connection:
    conn = sqlite3.connect(path, check_same_thread=False)
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS ble_packets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts REAL NOT NULL,
            dir TEXT,
            uuid TEXT,
            data TEXT,
            raw TEXT
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts REAL NOT NULL,
            type TEXT,
            payload TEXT
        )
        """
    )
    conn.commit()
    return conn


def main():
    conn = open_db()
    db_lock = threading.Lock()

    def insert_packet(ts, direction, uuid, data, raw):
        with db_lock:
            conn.execute(
                "INSERT INTO ble_packets (ts, dir, uuid, data, raw) VALUES (?, ?, ?, ?, ?)",
                (ts, direction, uuid, data, raw),
            )
            conn.commit()

    def insert_event(ts, msg):
        with db_lock:
            conn.execute(
                "INSERT INTO events (ts, type, payload) VALUES (?, ?, ?)",
                (ts, msg.get("type"), json.dumps(msg, default=str)),
            )
            conn.commit()

    def on_message(msg, _):
        ts = time.time()
        if msg["type"] == "send":
            p = msg["payload"]
            data = p["data"]
            try:
                asbytes = bytes.fromhex(data)
                as_str = asbytes.decode()
                insert_packet(ts, p["dir"], p["uuid"], as_str, data)
            except Exception:
                insert_packet(ts, p["dir"], p["uuid"], data, data)
        else:
            insert_event(ts, msg)

    def on_diagnostics(diag):
        print("!!!!" * 20)
        print("diag:", diag)
        insert_event(time.time(), {"type": "diagnostics", "payload": diag})

    compiler = frida.Compiler()
    compiler.on("diagnostics", on_diagnostics)
    bundle = compiler.build(
        "index.ts", project_root=str(Path.cwd() / "blemon" / "agent")
    )

    device = frida.get_device_manager().add_remote_device("192.168.1.5:42042")
    session = device.attach("Gadget")
    script = session.create_script(bundle)
    script.on("message", on_message)
    script.load()
    input(f"hooked, writing to {DB_PATH}, press Enter to quit\n")
    while True:
        inp = input()
        if inp.lower().strip() == "quit":
            break

    session.detach()
    conn.close()


if __name__ == "__main__":
    main()
