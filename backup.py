# capture.py
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import StreamingResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
import json
import threading
import queue
import pyshark
from datetime import datetime
import logging
import subprocess
import sqlite3
import asyncio
from typing import Tuple, Optional

app = FastAPI()

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("PacketCapture")

# CORS (allow everything for local dev)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# static & templates
app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")

# globals
packet_queue = queue.Queue(maxsize=5000)
stop_event = threading.Event()
capture_thread: Optional[threading.Thread] = None

# DB
DB_PATH = "register_ip.db"

# interface
INTERFACE = "wlp1s0"  # change if necessary


def init_db():
    """Create DB and table if it doesn't exist."""
    try:
        conn = sqlite3.connect(DB_PATH)
        cur = conn.cursor()
        cur.execute("""
            CREATE TABLE IF NOT EXISTS registered_ips (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip_address TEXT UNIQUE NOT NULL,
                device_name TEXT
            )
        """)
        conn.commit()
        conn.close()
        logger.info("Database initialized and table ensured.")
    except Exception as e:
        logger.error(f"Failed to initialize DB: {e}")


def db_check_ip(ip: str) -> Tuple[bool, Optional[str]]:
    """Return (is_registered, device_name or None)."""
    try:
        conn = sqlite3.connect(DB_PATH)
        cur = conn.cursor()
        cur.execute("SELECT device_name FROM registered_ips WHERE ip_address = ?", (ip,))
        row = cur.fetchone()
        conn.close()
        if row:
            return True, row[0]
        return False, None
    except Exception as e:
        logger.error(f"Database error checking IP {ip}: {e}")
        return False, None


def verify_tshark_installation() -> bool:
    try:
        subprocess.run(["tshark", "--version"], capture_output=True, text=True, check=True)
        logger.info("TShark is available")
        return True
    except Exception as e:
        logger.error(f"TShark not found or error: {e}")
        return False


def create_capture(interface: str) -> pyshark.LiveCapture:
    # display_filter picks interesting protocols
    return pyshark.LiveCapture(
        interface=interface,
        display_filter='tcp or udp or http or ssl or dns or icmp',
        use_json=False,
        include_raw=False,
        custom_parameters=['-l', '-n', '-q', '--no-promiscuous-mode']
    )


def process_packet(packet) -> Optional[dict]:
    """Convert pyshark Packet -> dict for sending to frontend."""
    try:
        pkt = {
            "time": getattr(packet, "sniff_time", datetime.now()).isoformat(),
            "protocol": "N/A",
            "src_ip": "N/A",
            "dst_ip": "N/A",
            "src_port": "N/A",
            "dst_port": "N/A",
            "length": "N/A",
            "info": ""
        }

        # Extract IP addresses
        if hasattr(packet, "ip"):
            pkt["src_ip"] = getattr(packet.ip, "src", "N/A")
            pkt["dst_ip"] = getattr(packet.ip, "dst", "N/A")
        elif hasattr(packet, "ipv6"):
            pkt["src_ip"] = getattr(packet.ipv6, "src", "N/A")
            pkt["dst_ip"] = getattr(packet.ipv6, "dst", "N/A")

        # Length
        length_val = None
        for attr in ("length", "len"):
            length_val = getattr(packet, attr, None)
            if length_val:
                break
        if not length_val and hasattr(packet, "frame_info") and hasattr(packet.frame_info, "len"):
            length_val = packet.frame_info.len
        if length_val:
            pkt["length"] = str(length_val)

        # Protocol detection
        if hasattr(packet, "tcp"):
            pkt["protocol"] = "TCP"
            pkt["src_port"] = getattr(packet.tcp, "srcport", "N/A")
            pkt["dst_port"] = getattr(packet.tcp, "dstport", "N/A")
            flags = getattr(packet.tcp, "flags", "")
            if flags:
                pkt["info"] = f"TCP flags: {flags}"
        elif hasattr(packet, "udp"):
            pkt["protocol"] = "UDP"
            pkt["src_port"] = getattr(packet.udp, "srcport", "N/A")
            pkt["dst_port"] = getattr(packet.udp, "dstport", "N/A")
            pkt["info"] = f"UDP {pkt['src_port']}→{pkt['dst_port']}"
        elif hasattr(packet, "icmp"):
            pkt["protocol"] = "ICMP"
            pkt["info"] = "ICMP"
        elif hasattr(packet, "http"):
            pkt["protocol"] = "HTTP"
            method = getattr(packet.http, "request_method", None)
            uri = getattr(packet.http, "request_uri", None)
            if method and uri:
                pkt["info"] = f"{method} {uri}"
        elif hasattr(packet, "ssl") or hasattr(packet, "tls"):
            pkt["protocol"] = "HTTPS"
            pkt["info"] = "SSL/TLS"

        # Check only src_ip for registration (source IP -> Known/Unknown)
        if pkt["src_ip"] not in ("N/A", None, ""):
            registered, device_name = db_check_ip(pkt["src_ip"])
            pkt["status"] = "Known User" if registered else "Unknown User"
            pkt["status_color"] = "green" if registered else "red"
            if device_name:
                pkt["device_name"] = device_name
        else:
            pkt["status"] = "Unknown User"
            pkt["status_color"] = "red"

        # Only send valid packets with both IPs
        if pkt["src_ip"] != "N/A" and pkt["dst_ip"] != "N/A":
            return pkt

    except Exception as e:
        logger.warning(f"Failed to process packet: {e}")
    return None


def capture_packets():
    """Thread target that captures packets and pushes dicts to packet_queue."""
    try:
        logger.info(f"Starting capture on interface: {INTERFACE}")
        capture = create_capture(INTERFACE)

        # sniff_continuously yields pyshark Packet objects
        for packet in capture.sniff_continuously():
            if stop_event.is_set():
                logger.info("Stop event set, breaking capture loop.")
                break
            try:
                pkt = process_packet(packet)
                if pkt:
                    try:
                        packet_queue.put(pkt, timeout=0.5)
                    except queue.Full:
                        logger.warning("Packet queue full; dropping packet")
            except Exception as e:
                logger.exception(f"Exception processing a packet: {e}")

        capture.close()
        logger.info("Capture thread exited.")
    except Exception as e:
        logger.exception(f"Capture failed: {e}")
        # provide a message to frontend
        packet_queue.put({
            "error": str(e),
            "time": datetime.now().isoformat(),
            "message": "Capture failed - check interface/permissions"
        })


@app.on_event("startup")
async def startup_event():
    init_db()
    verify_tshark_installation()


@app.get("/")
async def root(request: Request):
    # Renders templates/index.html — put your HTML into templates/index.html
    return templates.TemplateResponse("index.html", {"request": request})


# Accept both GET and POST for start (prevents 405 if frontend uses POST)
@app.api_route("/start", methods=["GET", "POST"])
def start_capture():
    global capture_thread
    if not verify_tshark_installation():
        raise HTTPException(status_code=500, detail="TShark is not installed or accessible")

    if capture_thread and capture_thread.is_alive():
        return {"status": "Already running"}

    # Clear any previous stop flag and start thread
    stop_event.clear()
    capture_thread = threading.Thread(target=capture_packets, daemon=True)
    capture_thread.start()
    logger.info("Capture thread started.")
    return {"status": "Capture started"}


# Accept both GET and POST for stop too
@app.api_route("/stop", methods=["GET", "POST"])
def stop_capture():
    stop_event.set()
    return {"status": "Capture stopped"}


@app.get("/stream")
async def stream_packets():
    async def event_stream():
        loop = asyncio.get_event_loop()
        while not stop_event.is_set() or not packet_queue.empty():
            try:
                # Use run_in_executor to avoid blocking event loop
                pkt = await loop.run_in_executor(None, packet_queue.get, True, 1)
                try:
                    yield f"data: {json.dumps(pkt)}\n\n"
                except Exception as e:
                    logger.warning(f"Failed to yield packet: {e}")
            except queue.Empty:
                # heartbeat to keep SSE alive
                yield ": heartbeat\n\n"
                await asyncio.sleep(0.1)
        logger.info("SSE generator exiting (stop event + empty queue).")

    headers = {
        'Cache-Control': 'no-cache',
        'Connection': 'keep-alive',
        'X-Accel-Buffering': 'no'
    }
    return StreamingResponse(event_stream(), media_type="text/event-stream", headers=headers)


# Optional: endpoints to manage registered IPs
@app.get("/registered")
def list_registered():
    try:
        conn = sqlite3.connect(DB_PATH)
        cur = conn.cursor()
        cur.execute("SELECT ip_address, device_name FROM registered_ips ORDER BY id")
        rows = cur.fetchall()
        conn.close()
        return {"registered": [{"ip": r[0], "device_name": r[1]} for r in rows]}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/registered")
def add_registered(ip_address: str, device_name: str = None):
    try:
        conn = sqlite3.connect(DB_PATH)
        cur = conn.cursor()
        cur.execute("INSERT OR IGNORE INTO registered_ips (ip_address, device_name) VALUES (?, ?)",
                    (ip_address, device_name))
        conn.commit()
        conn.close()
        return {"status": "ok"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
