let eventSource = null;

const startBtn = document.getElementById('startBtn');
const stopBtn = document.getElementById('stopBtn');
const tableBody = document.getElementById('packetTableBody');

startBtn.addEventListener('click', () => {
    if (!eventSource) {
        // Clear old packets
        tableBody.innerHTML = "";

        eventSource = new EventSource('http://localhost:8000/capture');

        eventSource.onmessage = function(event) {
            const packet = JSON.parse(event.data);
            addPacketToTable(packet);
        };

        eventSource.onerror = function() {
            console.log("Error occurred. Stopping capture.");
            stopCapture();
        };

        // Disable Start, Enable Stop
        startBtn.disabled = true;
        stopBtn.disabled = false;
    }
});

stopBtn.addEventListener('click', () => {
    stopCapture();
});

function stopCapture() {
    if (eventSource) {
        eventSource.close();
        eventSource = null;
    }
    startBtn.disabled = false;
    stopBtn.disabled = true;
}

function addPacketToTable(packet) {
    const row = document.createElement('tr');

    row.innerHTML = `
        <td>${packet.time}</td>
        <td>${packet.source_mac}</td>
        <td>${packet.destination_mac}</td>
        <td>${packet.source_ip}</td>
        <td>${packet.destination_ip}</td>
        <td>${packet.protocols}</td>
    `;

    tableBody.appendChild(row);
}
