from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import subprocess
from fastapi.responses import JSONResponse

app = FastAPI()

# 🛡 Allow CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allow all websites (or put your specific domain)
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/capture")
def capture_packets():
    try:
        output = subprocess.check_output([
            r"C:\Program Files\Wireshark\tshark.exe", "-i", "5", "-c", "25", "-T", "fields", "-e", "eth.src", "-e", "-e", "frame.protocols", "-e", "frame.time", "eth.dst", "-e", "ip.src", "-e", "ip.dst" 
        ], stderr=subprocess.STDOUT, text=True)

        # Parse the output
        packets = []
        for line in output.splitlines():
            fields = line.split('\t')
            if len(fields) >= 6:
                packets.append({
                    "source_mac": fields[0],
                     "time": fields[1],
                    "destination_mac": fields[2],
                    "protocols": fields[3],
                    "source_ip": fields[4],
                    "destination_ip": fields[5]
                    
                })

        return JSONResponse(content={"packets": packets})

    except subprocess.CalledProcessError as e:
        return JSONResponse(content={"error": str(e.output)}, status_code=500)
