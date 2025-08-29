class PacketCapture {
  constructor() {
    this.API_URL = "http://localhost:8000";
    this.packetCount = 0;
    this.eventSource = null;
    this.reconnectTimeout = null;
    this.capturedPackets = [];

    this.elements = {
      startBtn: document.getElementById('startBtn'),
      stopBtn: document.getElementById('stopBtn'),
      clearBtn: document.getElementById('clearBtn'),
      downloadBtn: document.getElementById('downloadBtn'),
      filterInput: document.getElementById('filterInput'),
      packetBody: document.getElementById('packetBody'),
      packetCounter: document.getElementById('packetCounter'),
      ipForm: document.getElementById('ipForm'),
      ipAddress: document.getElementById('ipAddress'),
      deviceName: document.getElementById('deviceName'),
      statusDiv: document.getElementById('statusDiv'),
      registeredIpsBody: document.getElementById('registeredIpsBody')
    };

    this.initEventListeners();
    this.loadRegisteredIps();
  }

  initEventListeners() {
    if (this.elements.startBtn) {
      this.elements.startBtn.addEventListener('click', () => this.startCapture());
    }
    if (this.elements.stopBtn) {
      this.elements.stopBtn.addEventListener('click', () => this.stopCapture());
    }
    if (this.elements.clearBtn) {
      this.elements.clearBtn.addEventListener('click', () => this.clearPackets());
    }
    if (this.elements.downloadBtn) {
      this.elements.downloadBtn.addEventListener('click', () => this.downloadPCAP());
    }
    if (this.elements.filterInput) {
      this.elements.filterInput.addEventListener('input', (e) => this.filterPackets(e.target.value));
    }
    if (this.elements.ipForm) {
      this.elements.ipForm.addEventListener('submit', (e) => this.registerIp(e));
    }
  }

  async loadRegisteredIps() {
    try {
      const response = await fetch(`${this.API_URL}/registered`);
      if (!response.ok) {
        throw new Error(`Failed to fetch registered IPs: ${response.statusText}`);
      }
      const data = await response.json();
      this.displayRegisteredIps(data.registered);
    } catch (error) {
      console.error('Error loading registered IPs:', error);
      this.updateStatus(`Failed to load registered IPs: ${error.message}`, 'status-error');
    }
  }

  displayRegisteredIps(ips) {
    if (!this.elements.registeredIpsBody) return;
    this.elements.registeredIpsBody.innerHTML = '';
    if (ips.length === 0) {
      const row = document.createElement('tr');
      row.innerHTML = '<td colspan="3" class="text-center">No registered IPs</td>';
      this.elements.registeredIpsBody.appendChild(row);
      return;
    }
    ips.forEach(ipData => {
      const row = document.createElement('tr');
      row.innerHTML = `
        <td>${ipData.ip}</td>
        <td>${ipData.device_name || 'N/A'}</td>
        <td><button class="btn btn-sm btn-danger" onclick="window.packetCapture.deleteIpFromTable('${ipData.ip}')">Delete</button></td>
      `;
      this.elements.registeredIpsBody.appendChild(row);
    });
  }

  async registerIp(event) {
    event.preventDefault();
    const ipAddress = this.elements.ipAddress ? this.elements.ipAddress.value : '';
    const deviceName = this.elements.deviceName ? this.elements.deviceName.value : '';

    this.updateStatus('', '');

    const ipRegex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)|(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$/;
    if (!ipAddress || !ipRegex.test(ipAddress)) {
      this.updateStatus('Please enter a valid IPv4 or IPv6 address', 'status-error');
      return;
    }

    try {
      const response = await fetch(`${this.API_URL}/registered`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ip_address: ipAddress, device_name: deviceName || null })
      });

      if (response.ok) {
        this.updateStatus('IP address successfully stored', 'status-active');
        if (this.elements.ipForm) this.elements.ipForm.reset();
        this.loadRegisteredIps();
        bootstrap.Modal.getInstance(document.getElementById('exampleModal')).hide();
      } else {
        const errorData = await response.json();
        this.updateStatus(`Failed to store IP: ${errorData.detail}`, 'status-error');
      }
    } catch (error) {
      this.updateStatus(`Failed to store IP: ${error.message}`, 'status-error');
    }
  }
  async deleteIpFromTable(ip) {
    try {
      // Most REST APIs expect the IP in the URL for DELETE
      const response = await fetch(`${this.API_URL}/registered/${ip}`, {
        method: 'DELETE',
        headers: { 'Content-Type': 'application/json' }
      });

      if (response.ok) {
        this.updateStatus(`IP ${ip} successfully deleted`, 'status-active');
        this.loadRegisteredIps();
      } else {
        const errorData = await response.json();
        this.updateStatus(`Failed to delete IP: ${errorData.detail}`, 'status-error');
      }
    } catch (error) {
      this.updateStatus(`Failed to delete IP: ${error.message}`, 'status-error');
    }
  }

  async startCapture() {
    this.updateStatus('Starting capture...', 'status-connecting');
    this.elements.startBtn.disabled = true;
    this.elements.stopBtn.disabled = false;
    this.elements.downloadBtn.disabled = true;

    try {
      const response = await fetch(`${this.API_URL}/start`, { method: 'POST' });
      if (!response.ok) {
        let errMsg = 'Failed to start capture';
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
      console.error('Start error:', error);
      this.updateStatus(`Error: ${error.message}`, 'status-error');
      this.elements.startBtn.disabled = false;
      this.elements.stopBtn.disabled = true;
    }
  }

  setupSSE() {
    if (this.eventSource) {
      this.eventSource.close();
      this.eventSource = null;
    }

    this.eventSource = new EventSource(`${this.API_URL}/stream`);

    this.eventSource.onopen = () => {
      console.log('SSE connected');
      this.updateStatus('Capture running', 'status-active');
    };

    this.eventSource.onmessage = (event) => {
      if (!event.data || event.data.trim().length === 0 || event.data.startsWith(':')) return;

      try {
        const packet = JSON.parse(event.data);
        this.capturedPackets.push(packet);
        this.displayPacket(packet);
        this.updatePacketCounter(this.packetCount);

        if (this.elements.filterInput && this.elements.filterInput.value) {
          this.filterPackets(this.elements.filterInput.value);
        }
      } catch (error) {
        console.error('Packet parsing error:', error);
      }
    };

    this.eventSource.onerror = () => {
      console.warn('SSE disconnected. Trying to reconnect...');
      this.updateStatus('Connection lost. Reconnecting...', 'status-warning');
      this.stopCapture(false);
      if (this.reconnectTimeout) clearTimeout(this.reconnectTimeout);
      this.reconnectTimeout = setTimeout(() => this.setupSSE(), 3000);
    };
  }

  displayPacket(packet) {
    if (!this.elements.packetBody) return;
    const row = document.createElement('tr');
    row.className = 'new-packet';

    const safeGet = (obj, prop, fallback = 'N/A') =>
      obj && obj[prop] !== undefined && obj[prop] !== null ? obj[prop] : fallback;

    const protocolRaw = String(safeGet(packet, 'protocol', 'unknown'));
    const protocol = protocolRaw.toLowerCase();
    const protocolClass = ['tcp', 'udp', 'http', 'https', 'dns', 'icmp'].includes(protocol)
      ? `protocol-${protocol}` : 'protocol-other';

    const formattedTime = safeGet(packet, 'time') ? new Date(safeGet(packet, 'time')).toLocaleTimeString() : 'N/A';
    const srcIp = safeGet(packet, 'src_ip');
    const dstIp = safeGet(packet, 'dst_ip');
    const statusRaw = safeGet(packet, 'status', 'Unknown User');
    const deviceName = safeGet(packet, 'device_name', '');

    let srcBadge = '';
    if (statusRaw === 'Known User') {
      srcBadge = ' <span class="badge bg-success ms-2">Known User</span>';
    } else if (statusRaw === 'Unknown User') {
      srcBadge = ' <span class="badge bg-danger ms-2">Unknown User</span>';
    }

    const deviceText = deviceName ? ` <small class="text-muted">(${deviceName})</small>` : '';

    row.innerHTML = `
      <td>${++this.packetCount}</td>
      <td>${formattedTime}</td>
      <td class="${protocolClass}">${protocolRaw}</td>
      <td>${srcIp}${srcBadge}${deviceText}</td>
      <td>${dstIp}</td>
      <td>${safeGet(packet, 'src_port')}</td>
      <td>${safeGet(packet, 'dst_port')}</td>
      <td>${safeGet(packet, 'info')}</td>
    `;

    this.elements.packetBody.prepend(row);
  }

  stopCapture(hardStop = true) {
    this.updateStatus('Stopping capture...', 'status-connecting');
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
      fetch(`${this.API_URL}/stop`, { method: 'POST' })
        .then(async res => {
          if (!res.ok) {
            let msg = 'Stop failed';
            try { msg = (await res.json()).detail || JSON.stringify(await res.json()); } catch { msg = await res.text(); }
            throw new Error(msg);
          }
          this.updateStatus('Capture stopped. You can now download PCAP.', 'status-stopped');
          this.elements.startBtn.disabled = false;
          this.elements.stopBtn.disabled = true;
          this.elements.downloadBtn.disabled = false;
        })
        .catch(error => {
          console.error('Stop error:', error);
          this.updateStatus(`Error: ${error.message}`, 'status-error');
          this.elements.startBtn.disabled = false;
        });
    } else {
      this.updateStatus('Capture stopped (soft). You can now download PCAP.', 'status-stopped');
      this.elements.startBtn.disabled = false;
      this.elements.stopBtn.disabled = true;
      this.elements.downloadBtn.disabled = false;
    }
  }

  clearPackets() {
    if (this.elements.packetBody) {
      this.elements.packetBody.innerHTML = '';
    }
    this.packetCount = 0;
    this.capturedPackets = [];
    this.updatePacketCounter(0);
    this.updateStatus('Cleared all packets', 'status-ready');
  }

  filterPackets(filterText) {
    if (!this.elements.packetBody) return;
    const rows = this.elements.packetBody.querySelectorAll('tr');

    const filters = filterText
      .trim()
      .toLowerCase()
      .split(/\s+/)
      .map(f => {
        const [key, ...rest] = f.split(':');
        return rest.length ? { key, value: rest.join(':').toLowerCase() } : { key: 'any', value: key.toLowerCase() };
      });

    rows.forEach(row => {
      const cells = row.cells;
      const rowData = {
        number: (cells[0]?.textContent || '').toLowerCase(),
        time: (cells[1]?.textContent || '').toLowerCase(),
        protocol: (cells[2]?.textContent || '').toLowerCase(),
        src_ip: (cells[3]?.textContent || '').toLowerCase(),
        dst_ip: (cells[4]?.textContent || '').toLowerCase(),
        src_port: (cells[5]?.textContent || '').toLowerCase(),
        dst_port: (cells[6]?.textContent || '').toLowerCase(),
        info: (cells[7]?.textContent || '').toLowerCase()
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

  downloadPCAP() {
  window.location.href = `${this.API_URL}/download-csv`;
  }

  updateStatus(message, statusClass) {
    if (this.elements.statusDiv) {
      this.elements.statusDiv.textContent = message;
      this.elements.statusDiv.className = `mb-3 text-center ${statusClass}`;
    } else {
      console.warn('Status div not found; cannot update status message');
    }
  }

  updatePacketCounter(count) {
    if (this.elements.packetCounter) {
      this.elements.packetCounter.textContent = `${count} packet${count !== 1 ? 's' : ''} captured`;
      this.elements.packetCounter.className = `packet-counter ${count > 0 ? 'text-primary' : 'text-secondary'}`;
    }
  }
}

document.addEventListener('DOMContentLoaded', () => {
  window.packetCapture = new PacketCapture();
});