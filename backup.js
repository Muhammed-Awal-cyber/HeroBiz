// static/call.js
class PacketCapture {
  constructor() {
    this.API_URL = "http://localhost:8000";
    this.packetCount = 0;
    this.eventSource = null;
    this.reconnectTimeout = null;
    this.capturedPackets = []; // Store packets locally for download

    this.elements = {
      startBtn: document.getElementById('startBtn'),
      stopBtn: document.getElementById('stopBtn'),
      clearBtn: document.getElementById('clearBtn'),
      filterInput: document.getElementById('filterInput'),
      downloadBtn: document.getElementById('downloadBtn'),
      autoScroll: document.getElementById('autoScroll'),
      statusDiv: document.getElementById('statusDiv'),
      packetBody: document.getElementById('packetBody'),
      packetCounter: document.getElementById('packetCounter')
    };

    this.initEventListeners();
  }

  initEventListeners() {
    this.elements.startBtn.addEventListener('click', () => this.startCapture());
    this.elements.stopBtn.addEventListener('click', () => this.stopCapture());
    this.elements.clearBtn.addEventListener('click', () => this.clearPackets());
    this.elements.downloadBtn.addEventListener('click', () => this.downloadCSV());
    this.elements.filterInput.addEventListener('input', (e) => this.filterPackets(e.target.value));
  }

  async startCapture() {
    this.updateStatus("Starting capture...", "status-connecting");
    this.elements.startBtn.disabled = true;
    this.elements.stopBtn.disabled = false;

    try {
      // send POST to /start (backend accepts GET or POST now)
      const response = await fetch(`${this.API_URL}/start`, { method: "POST" });
      if (!response.ok) {
        let errMsg = "Failed to start capture";
        try {
          const body = await response.json();
          errMsg = body.detail || body.error || JSON.stringify(body);
        } catch {
          try { errMsg = await response.text(); } catch {}
        }
        throw new Error(errMsg);
      }
      this.setupSSE();
    } catch (error) {
      console.error("Start error:", error);
      this.updateStatus(`Error: ${error.message}`, "status-error");
      this.elements.startBtn.disabled = false;
      this.elements.stopBtn.disabled = true;
      alert(`Start failed: ${error.message}`);
    }
  }

  setupSSE() {
    if (this.eventSource) {
      this.eventSource.close();
      this.eventSource = null;
    }

    this.eventSource = new EventSource(`${this.API_URL}/stream`);

    this.eventSource.onopen = () => {
      console.log("SSE connected");
      this.updateStatus("Capture running", "status-active");
    };

    this.eventSource.onmessage = (event) => {
      // ignore heartbeat/comment lines
      if (!event.data || event.data.trim().length === 0 || event.data.startsWith(":")) return;

      try {
        const packet = JSON.parse(event.data);
        this.capturedPackets.push(packet);
        this.displayPacket(packet);
        this.updatePacketCounter(this.packetCount);

        if (this.elements.filterInput.value) {
          this.filterPackets(this.elements.filterInput.value);
        }
      } catch (error) {
        console.error("Packet parsing error:", error);
      }
    };

    this.eventSource.onerror = () => {
      console.warn("SSE disconnected. Trying to reconnect...");
      this.updateStatus("Connection lost. Reconnecting...", "status-warning");
      // soft stop SSE locally
      this.stopCapture(false);
      if (this.reconnectTimeout) clearTimeout(this.reconnectTimeout);
      this.reconnectTimeout = setTimeout(() => this.setupSSE(), 3000);
    };
  }

  displayPacket(packet) {
    const row = document.createElement('tr');
    row.className = 'new-packet';

    const safeGet = (obj, prop, fallback = 'N/A') =>
      obj && obj[prop] !== undefined && obj[prop] !== null ? obj[prop] : fallback;

    const protocolRaw = String(safeGet(packet, 'protocol', 'unknown'));
    const protocol = protocolRaw.toLowerCase();
    const protocolClass = ['tcp', 'udp', 'http', 'https', 'dns', 'icmp'].includes(protocol)
      ? `protocol-${protocol}` : 'protocol-other';

    const formattedTime = safeGet(packet, 'time') ? new Date(safeGet(packet, 'time')).toLocaleTimeString() : 'N/A';

    const infoText = safeGet(packet, 'info', '');
    const deviceName = safeGet(packet, 'device_name', '');
    const statusRaw = safeGet(packet, 'status', 'Unknown User'); // "Known User" or "Unknown User"
    const statusLower = (statusRaw + '').toLowerCase();

    // Build Source IP cell with a badge showing Known/Unknown user
    const srcIp = safeGet(packet, 'src_ip');
    let srcBadge = '';
    if (statusRaw === 'Known User') {
      srcBadge = ' <span class="badge bg-success ms-2">Known User</span>';
    } else if (statusRaw === 'Unknown User') {
      srcBadge = ' <span class="badge bg-danger ms-2">Unknown User</span>';
      // mark the whole row red-ish for unknown source IPs
      row.style.backgroundColor = 'rgba(255, 0, 0, 0.06)';
    }

    // also include device name small text if present
    const deviceText = deviceName ? ` <small class="text-muted">(${deviceName})</small>` : '';

    row.innerHTML = `
      <td>${++this.packetCount}</td>
      <td>${formattedTime}</td>
      <td class="${protocolClass}">${protocolRaw}</td>
      <td>${srcIp}${srcBadge}${deviceText}</td>
      <td>${safeGet(packet, 'dst_ip')}</td>
      <td>${safeGet(packet, 'src_port')}</td>
      <td>${safeGet(packet, 'dst_port')}</td>
      <td>${infoText}</td>
    `;

    // Prepend newest
    this.elements.packetBody.prepend(row);

    // Auto-scroll (keeps behavior)
    if (this.elements.autoScroll.checked) {
      const container = this.elements.packetBody.parentElement;
      container.scrollTop = 0;
    }
  }

  stopCapture(hardStop = true) {
    this.updateStatus("Stopping capture...", "status-connecting");
    this.elements.stopBtn.disabled = true;

    if (this.eventSource) {
      this.eventSource.close();
      this.eventSource = null;
    }
    if (this.reconnectTimeout) {
      clearTimeout(this.reconnectTimeout);
      this.reconnectTimeout = null;
    }

    if (hardStop) {
      // send POST to /stop (backend accepts GET/POST)
      fetch(`${this.API_URL}/stop`, { method: "POST" })
        .then(async res => {
          if (!res.ok) {
            let msg = 'Stop failed';
            try { msg = (await res.json()).detail || JSON.stringify(await res.json()); } catch { msg = await res.text(); }
            throw new Error(msg);
          }
          this.updateStatus("Capture stopped", "status-stopped");
          this.elements.startBtn.disabled = false;
          this.elements.stopBtn.disabled = true;
        })
        .catch(error => {
          console.error("Stop error:", error);
          this.updateStatus(`Error: ${error.message}`, "status-error");
          this.elements.startBtn.disabled = false;
        });
    } else {
      this.updateStatus("Capture stopped (soft)", "status-stopped");
      this.elements.startBtn.disabled = false;
      this.elements.stopBtn.disabled = true;
    }
  }

  clearPackets() {
    this.elements.packetBody.innerHTML = '';
    this.packetCount = 0;
    this.capturedPackets = [];
    this.updatePacketCounter(0);
    this.updateStatus("Cleared all packets", "status-ready");
  }

  filterPackets(filterText) {
    const rows = this.elements.packetBody.querySelectorAll('tr');

    const filters = filterText
      .trim()
      .toLowerCase()
      .split(/\s+/)
      .map(f => {
        const [key, ...rest] = f.split(':');
        return rest.length ? { key, value: rest.join(':') } : { key: 'any', value: key };
      });

    rows.forEach(row => {
      const cells = row.cells;
      const rowData = {
        number: (cells[0] && cells[0].textContent || '').toLowerCase(),
        time: (cells[1] && cells[1].textContent || '').toLowerCase(),
        protocol: (cells[2] && cells[2].textContent || '').toLowerCase(),
        src_ip: (cells[3] && cells[3].textContent || '').toLowerCase(),
        dst_ip: (cells[4] && cells[4].textContent || '').toLowerCase(),
        src_port: (cells[5] && cells[5].textContent || '').toLowerCase(),
        dst_port: (cells[6] && cells[6].textContent || '').toLowerCase(),
        info: (cells[7] && cells[7].textContent || '').toLowerCase()
      };

      const matchAll = filters.every(f => {
        if (f.key === 'protocol') return rowData.protocol.includes(f.value);
        if (f.key === 'ip') return rowData.src_ip.includes(f.value) || rowData.dst_ip.includes(f.value);
        if (f.key === 'src_ip') return rowData.src_ip.includes(f.value);
        if (f.key === 'dst_ip') return rowData.dst_ip.includes(f.value);
        if (f.key === 'port') return rowData.src_port.includes(f.value) || rowData.dst_port.includes(f.value);
        if (f.key === 'src_port') return rowData.src_port.includes(f.value);
        if (f.key === 'dst_port') return rowData.dst_port.includes(f.value);
        if (f.key === 'info') return rowData.info.includes(f.value);
        if (f.key === 'any') {
          return Object.values(rowData).some(val => val.includes(f.value));
        }
        return true;
      });

      row.style.display = matchAll ? '' : 'none';
    });
  }

  downloadCSV() {
    if (this.capturedPackets.length === 0) {
      alert("No packets to download!");
      return;
    }

    const header = ["Number", "Time", "Protocol", "Source IP", "Destination IP", "Source Port", "Destination Port", "Info", "Status", "Device"];
    const rows = this.capturedPackets.map((p, i) => [
      i + 1,
      p.time || '',
      p.protocol || '',
      p.src_ip || '',
      p.dst_ip || '',
      p.src_port || '',
      p.dst_port || '',
      p.info || '',
      p.status || '',
      p.device_name || ''
    ]);

    const csvContent = [header, ...rows].map(e => e.join(",")).join("\n");
    const blob = new Blob([csvContent], { type: "text/csv;charset=utf-8;" });
    const url = URL.createObjectURL(blob);

    const a = document.createElement("a");
    a.href = url;
    a.download = `packets_${new Date().toISOString().replace(/[:.]/g, '-')}.csv`;
    a.click();
    URL.revokeObjectURL(url);
  }

  updateStatus(message, statusClass) {
    this.elements.statusDiv.textContent = message;
    this.elements.statusDiv.className = `p-3 mb-3 text-white text-center rounded ${statusClass}`;
  }

  updatePacketCounter(count) {
    this.elements.packetCounter.textContent = `${count} packet${count !== 1 ? 's' : ''}`;
    this.elements.packetCounter.className = `badge ${count > 0 ? 'bg-primary' : 'bg-secondary'}`;
  }
}

document.addEventListener('DOMContentLoaded', () => {
  window.packetCapture = new PacketCapture();
});
