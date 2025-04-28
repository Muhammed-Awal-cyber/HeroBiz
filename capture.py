import subprocess
from fastapi import FastAPI
from fastapi.responses import StreamingResponse
from fastapi.middleware.cors import CORSMiddleware
import json

app = FastAPI()

# Allow CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/capture")
def capture_packets():
    def packet_generator():
        process = subprocess.Popen([
            r"C:\Program Files\Wireshark\tshark.exe",
            "-i", "5",
            "-l",  # Make tshark line-buffered (important for real-time)
            "-T", "fields",
            "-e", "frame.time",
            "-e", "eth.src",
            "-e", "eth.dst",
            "-e", "ip.src",
            "-e", "ip.dst",
            "-e", "frame.protocols"
        ], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

        for line in process.stdout:
            fields = line.strip().split('\t')
            if len(fields) >= 6:
                packet = {
                    "time": fields[0],
                    "source_mac": fields[1],
                    "destination_mac": fields[2],
                    "source_ip": fields[3],
                    "destination_ip": fields[4],
                    "protocols": fields[5]
                }
                yield f"data: {json.dumps(packet)}\n\n"

    return StreamingResponse(packet_generator(), media_type="text/event-stream")
