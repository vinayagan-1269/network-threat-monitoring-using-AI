// ============================================================
// NETWORK THREAT MONITOR - DASHBOARD SCRIPT
// ============================================================


// ------------------------------------------------------------
// LOAD NETWORK INTERFACES
// ------------------------------------------------------------
// ============================================================
// REAL-TIME THREAT TRACKING
// ============================================================

let knownAlertIds = new Set();

let alertsInitialized = false;

async function loadInterfaces() {

    try {

        const response = await fetch("/api/interfaces");

        const data = await response.json();

        const selector =
            document.getElementById("interface-select");

        selector.innerHTML = "";

        data.interfaces.forEach(interfaceInfo => {

            const option =
                document.createElement("option");

            option.value = interfaceInfo.number;

            option.textContent =
                `${interfaceInfo.number} - ${interfaceInfo.description}`;

            selector.appendChild(option);

        });


        // Select Wi-Fi adapter by default if available

        const wifiInterface =
            data.interfaces.find(
                interfaceInfo => interfaceInfo.number === 5
            );

        if (wifiInterface) {

            selector.value = "5";

        }

    }

    catch (error) {

        console.error(
            "Failed to load interfaces:",
            error
        );

    }
}


// ------------------------------------------------------------
// START MONITORING
// ------------------------------------------------------------

async function startMonitoring() {

    const selector =
        document.getElementById("interface-select");

    const interfaceNumber =
        selector.value;


    if (!interfaceNumber) {

        alert(
            "Please select a network interface."
        );

        return;

    }


    try {

        const response = await fetch(
            "/api/start",
            {
                method: "POST",

                headers: {
                    "Content-Type": "application/json"
                },

                body: JSON.stringify({
                    interface:
                        parseInt(interfaceNumber)
                })
            }
        );


        const data =
            await response.json();


        console.log(
            "Start response:",
            data
        );


        updateStatus();

    }

    catch (error) {

        console.error(
            "Failed to start monitoring:",
            error
        );

    }
}


// ------------------------------------------------------------
// STOP MONITORING
// ------------------------------------------------------------

async function stopMonitoring() {

    try {

        const response = await fetch(
            "/api/stop",
            {
                method: "POST"
            }
        );


        const data =
            await response.json();


        console.log(
            "Stop response:",
            data
        );


        updateStatus();

    }

    catch (error) {

        console.error(
            "Failed to stop monitoring:",
            error
        );

    }
}


// ------------------------------------------------------------
// CHECK MONITORING STATUS
// ------------------------------------------------------------

async function updateStatus() {

    try {

        const response =
            await fetch("/api/status");

        const data =
            await response.json();


        const statusElement =
            document.querySelector(".status");


        if (!statusElement) {
            return;
        }


        if (data.running) {

            statusElement.innerHTML =
                '<span class="status-dot"></span> Monitoring';

        }

        else {

            statusElement.innerHTML =
                '<span class="status-dot stopped"></span> Stopped';

        }

    }

    catch (error) {

        console.error(
            "Failed to get monitoring status:",
            error
        );

    }
}


// ------------------------------------------------------------
// LOAD STATISTICS
// ------------------------------------------------------------

async function loadStats() {

    try {

        const response =
            await fetch("/api/stats");

        const data =
            await response.json();


        document.getElementById("total-flows").textContent =
            data.total_flows ?? 0;

        document.getElementById("benign").textContent =
            data.benign ?? 0;

        document.getElementById("portscan").textContent =
            data.portscan ?? 0;

        document.getElementById("ddos").textContent =
            data.ddos ?? 0;

    }

    catch (error) {

        console.error(
            "Failed to load statistics:",
            error
        );

    }
}


// ------------------------------------------------------------
// LOAD CURRENT FLOW DATA
// ------------------------------------------------------------

async function loadFlows() {

    try {

        const response =
            await fetch("/api/flows");

        const flows =
            await response.json();


        const table =
            document.getElementById("flow-table");


        if (!table) {
            return;
        }


        table.innerHTML = "";


        flows.forEach(flow => {

            const row =
                document.createElement("tr");
			
			row.classList.add("flow-row");
    
            row.addEventListener(
                "click",
                () => openFlowModal(flow)
            );


            const prediction =
                flow.Prediction ||
                flow.prediction ||
                "UNKNOWN";


            let predictionClass = "";


            if (prediction === "BENIGN") {

                predictionClass =
                    "prediction-benign";

            }

            else if (prediction === "PortScan") {

                predictionClass =
                    "prediction-portscan";

            }

            else if (prediction === "DDoS") {

                predictionClass =
                    "prediction-ddos";

            }


            row.innerHTML = `

                <td>
                    ${flow.timestamp || ""}
                </td>

                <td>
                    ${flow.src_ip || ""}
                </td>

                <td>
                    ${flow.dst_ip || ""}
                </td>

                <td>
                    ${flow.src_port || ""}
                </td>

                <td>
                    ${flow.dst_port || ""}
                </td>

                <td>
                    ${flow.protocol || ""}
                </td>

                <td>
                    ${flow.tot_fwd_pkts || 0}
                </td>

                <td>
                    ${flow.tot_bwd_pkts || 0}
                </td>

                <td>
                    ${flow.flow_duration || 0}
                </td>

                <td class="${predictionClass}">
                    ${prediction}
                </td>

            `;


            table.appendChild(row);

        });

    }

    catch (error) {

        console.error(
            "Failed to load flows:",
            error
        );

    }
}


// ------------------------------------------------------------
// LOAD FLOW HISTORY
// ------------------------------------------------------------

async function loadHistory() {

    try {

        const response =
            await fetch("/api/history");

        const data =
            await response.json();


        if (data.status !== "success") {
            return;
        }


        // History is currently used by the
        // dashboard's flow table.

        renderHistory(data.flows);

    }

    catch (error) {

        console.error(
            "Failed to load flow history:",
            error
        );

    }
}

// ------------------------------------------------------------
// RENDER MONITORING HISTORY
// ------------------------------------------------------------

function renderHistory(flows) {

    const table =
        document.getElementById("history-table");

    if (!table) {
        return;
    }

    table.innerHTML = "";

    flows.forEach(flow => {

        const row =
            document.createElement("tr");

        const prediction =
            flow.prediction ||
            flow.Prediction ||
            "UNKNOWN";

        let predictionClass = "";

        if (prediction === "BENIGN") {
            predictionClass =
                "prediction-benign";
        }

        else if (prediction === "PortScan") {
            predictionClass =
                "prediction-portscan";
        }

        else if (prediction === "DDoS") {
            predictionClass =
                "prediction-ddos";
        }

        row.innerHTML = `

            <td>${flow.timestamp || ""}</td>

            <td>${flow.src_ip || ""}</td>

            <td>${flow.dst_ip || ""}</td>

            <td>${flow.src_port || ""}</td>

            <td>${flow.dst_port || ""}</td>

            <td>${flow.protocol || ""}</td>

            <td>${flow.tot_fwd_pkts || 0}</td>

            <td>${flow.tot_bwd_pkts || 0}</td>

            <td>${flow.flow_duration || 0}</td>

            <td class="${predictionClass}">
                ${prediction}
            </td>

        `;

        table.appendChild(row);

    });
}

// ------------------------------------------------------------
// RENDER HISTORY FLOWS
// ------------------------------------------------------------

function renderFlows(flows) {

    const table =
        document.getElementById("flow-table");


    if (!table) {
        return;
    }


    table.innerHTML = "";


    flows.forEach(flow => {

    const row =
        document.createElement("tr");

    row.classList.add("flow-row");

    row.addEventListener(
        "click",
        () => openFlowModal(flow)
    );


    const prediction =
        flow.prediction ||
        flow.Prediction ||
        "UNKNOWN";


        let predictionClass = "";


        if (prediction === "BENIGN") {

            predictionClass =
                "prediction-benign";

        }

        else if (prediction === "PortScan") {

            predictionClass =
                "prediction-portscan";

        }

        else if (prediction === "DDoS") {

            predictionClass =
                "prediction-ddos";

        }


        row.innerHTML = `

            <td>
                ${flow.timestamp || ""}
            </td>

            <td>
                ${flow.src_ip || ""}
            </td>

            <td>
                ${flow.dst_ip || ""}
            </td>

            <td>
                ${flow.src_port || ""}
            </td>

            <td>
                ${flow.dst_port || ""}
            </td>

            <td>
                ${flow.protocol || ""}
            </td>

            <td>
                ${flow.tot_fwd_pkts || 0}
            </td>

            <td>
                ${flow.tot_bwd_pkts || 0}
            </td>

            <td>
                ${flow.flow_duration || 0}
            </td>

            <td class="${predictionClass}">
                ${prediction}
            </td>

        `;


        table.appendChild(row);

    });
}


// ------------------------------------------------------------
// LOAD THREAT ALERTS
// ------------------------------------------------------------

async function loadAlerts() {

    try {

        const response =
            await fetch("/api/alerts");

        const data =
            await response.json();


        if (data.status !== "success") {
            return;
        }


        const alerts =
            data.alerts || [];


        // ----------------------------------------------------
        // DETECT NEW THREATS
        // ----------------------------------------------------

        const newAlerts = [];


        alerts.forEach(alert => {

            const alertId =
                alert.id;


            if (
                alertId !== undefined &&
                !knownAlertIds.has(alertId)
            ) {

                newAlerts.push(alert);

            }

        });


        // ----------------------------------------------------
        // FIRST LOAD
        // ----------------------------------------------------

        /*
            Do not show notifications for old threats
            already present when the dashboard opens.
        */

        if (!alertsInitialized) {

            alerts.forEach(alert => {

                if (alert.id !== undefined) {

                    knownAlertIds.add(
                        alert.id
                    );

                }

            });


            alertsInitialized = true;

        }


        // ----------------------------------------------------
        // NEW THREAT DETECTED
        // ----------------------------------------------------

        else if (newAlerts.length > 0) {

            newAlerts.forEach(alert => {

                if (alert.id !== undefined) {

                    knownAlertIds.add(
                        alert.id
                    );

                }

            });


            // Show the newest threat

            const newestThreat =
                newAlerts[0];


            showThreatNotification(
                newestThreat
            );

        }


        // ----------------------------------------------------
        // RENDER ALERT TABLE
        // ----------------------------------------------------

        renderAlerts(alerts);

    }

    catch (error) {

        console.error(
            "Failed to load threat alerts:",
            error
        );

    }

}

// ------------------------------------------------------------
// SHOW THREAT NOTIFICATION
// ------------------------------------------------------------

function showThreatNotification(alert) {

    const notification =
        document.getElementById(
            "threat-notification"
        );


    const message =
        document.getElementById(
            "notification-message"
        );


    if (!notification || !message) {
        return;
    }


    const prediction =
        alert.prediction ||
        "UNKNOWN";


    const source =
        alert.src_ip ||
        "Unknown source";


    const destination =
        alert.dst_ip ||
        "Unknown destination";


    message.innerHTML = `

        <strong>${prediction}</strong>

        detected

        <br>

        ${source}

        →

        ${destination}

    `;


    notification.style.display =
        "flex";


    // Automatically hide after 8 seconds

    setTimeout(
        () => {

            hideThreatNotification();

        },
        8000
    );

}


// ------------------------------------------------------------
// HIDE THREAT NOTIFICATION
// ------------------------------------------------------------

function hideThreatNotification() {

    const notification =
        document.getElementById(
            "threat-notification"
        );


    if (notification) {

        notification.style.display =
            "none";

    }

}

// ------------------------------------------------------------
// RENDER THREAT ALERTS
// ------------------------------------------------------------

function renderAlerts(alerts) {

    const container =
        document.getElementById(
            "alerts-container"
        );


    if (!container) {
        return;
    }


    // No threats

    if (!alerts || alerts.length === 0) {

        container.innerHTML = `

            <div class="no-alerts">

                ✓ No threats detected

            </div>

        `;

        return;
    }


    // Threats exist

    container.innerHTML = alerts.map(
        alert => {

            let threatClass = "";


            if (alert.prediction === "DDoS") {

                threatClass =
                    "alert-ddos";

            }

            else if (
                alert.prediction === "PortScan"
            ) {

                threatClass =
                    "alert-portscan";

            }


            return `

                <div class="alert-row ${threatClass}">

                    <div>
                        ${alert.timestamp || "-"}
                    </div>

                    <div>
                        ${alert.src_ip || "-"}
                    </div>

                    <div>
                        ${alert.dst_ip || "-"}
                    </div>

                    <div>
                        ${alert.src_port || "-"}
                    </div>

                    <div>
                        ${alert.dst_port || "-"}
                    </div>

                    <div class="threat-label">
                        ${alert.prediction || "UNKNOWN"}
                    </div>

                </div>

            `;

        }
    ).join("");

}


// ------------------------------------------------------------
// UPDATE LAST UPDATED TIME
// ------------------------------------------------------------

function updateLastUpdated() {

    const element =
        document.getElementById(
            "last-updated"
        );


    if (!element) {
        return;
    }


    const now =
        new Date();


    element.textContent =
        "Last updated: " +
        now.toLocaleTimeString();

}


// ------------------------------------------------------------
// UPDATE COMPLETE DASHBOARD
// ------------------------------------------------------------

// ------------------------------------------------------------
// UPDATE COMPLETE DASHBOARD
// ------------------------------------------------------------

async function updateDashboard() {

    await Promise.all([

        loadStats(),

        loadFlows(),

        loadAlerts(),

        loadCharts(),

        loadMonitoringHistory()

    ]);

    const now = new Date();

    const lastUpdated =
        document.getElementById("last-updated");

    if (lastUpdated) {

        lastUpdated.textContent =
            "Last updated: " +
            now.toLocaleTimeString();

    }

}

// ------------------------------------------------------------
// INITIAL LOAD
// ------------------------------------------------------------

loadInterfaces();

updateDashboard();

updateStatus();


// ------------------------------------------------------------
// AUTOMATIC REFRESH
// ------------------------------------------------------------

// Dashboard data every 5 seconds

setInterval(
    updateDashboard,
    5000
);


// Monitoring status every 2 seconds

setInterval(
    updateStatus,
    2000
);
// ------------------------------------------------------------
// OPEN FLOW DETAILS
// ------------------------------------------------------------

function openFlowModal(flow) {

    const modal =
        document.getElementById("flow-modal");

    const details =
        document.getElementById("flow-details");


    if (!modal || !details) {
        return;
    }


    const prediction =
        flow.prediction ||
        flow.Prediction ||
        "UNKNOWN";


    let predictionClass = "";


    if (prediction === "BENIGN") {

        predictionClass = "benign";

    }

    else if (prediction === "PortScan") {

        predictionClass = "portscan";

    }

    else if (prediction === "DDoS") {

        predictionClass = "ddos";

    }


    details.innerHTML = `

        <div
            class="flow-detail-prediction
            ${predictionClass}"
        >
            ${prediction}
        </div>


        <div class="flow-detail-item">

            <span class="flow-detail-label">
                Timestamp
            </span>

            <span class="flow-detail-value">
                ${flow.timestamp || "-"}
            </span>

        </div>


        <div class="flow-detail-item">

            <span class="flow-detail-label">
                Source IP
            </span>

            <span class="flow-detail-value">
                ${flow.src_ip || "-"}
            </span>

        </div>


        <div class="flow-detail-item">

            <span class="flow-detail-label">
                Destination IP
            </span>

            <span class="flow-detail-value">
                ${flow.dst_ip || "-"}
            </span>

        </div>


        <div class="flow-detail-item">

            <span class="flow-detail-label">
                Source Port
            </span>

            <span class="flow-detail-value">
                ${flow.src_port || "-"}
            </span>

        </div>


        <div class="flow-detail-item">

            <span class="flow-detail-label">
                Destination Port
            </span>

            <span class="flow-detail-value">
                ${flow.dst_port || "-"}
            </span>

        </div>


        <div class="flow-detail-item">

            <span class="flow-detail-label">
                Protocol
            </span>

            <span class="flow-detail-value">
                ${flow.protocol || "-"}
            </span>

        </div>


        <div class="flow-detail-item">

            <span class="flow-detail-label">
                Forward Packets
            </span>

            <span class="flow-detail-value">
                ${flow.tot_fwd_pkts || 0}
            </span>

        </div>


        <div class="flow-detail-item">

            <span class="flow-detail-label">
                Backward Packets
            </span>

            <span class="flow-detail-value">
                ${flow.tot_bwd_pkts || 0}
            </span>

        </div>


        <div class="flow-detail-item">

            <span class="flow-detail-label">
                Flow Duration
            </span>

            <span class="flow-detail-value">
                ${flow.flow_duration || 0}
            </span>

        </div>

    `;


    modal.style.display = "flex";

}


// ------------------------------------------------------------
// CLOSE FLOW DETAILS
// ------------------------------------------------------------

function closeFlowModal() {

    const modal =
        document.getElementById("flow-modal");


    if (modal) {

        modal.style.display = "none";

    }

}


// ------------------------------------------------------------
// CLOSE MODAL WHEN CLICKING OUTSIDE
// ------------------------------------------------------------

window.addEventListener(
    "click",
    function(event) {

        const modal =
            document.getElementById("flow-modal");


        if (
            modal &&
            event.target === modal
        ) {

            closeFlowModal();

        }

    }
);

// ============================================================
// TRAFFIC & THREAT CHARTS
// ============================================================

let trafficChart = null;
let threatChart = null;


// ------------------------------------------------------------
// LOAD CHART DATA
// ------------------------------------------------------------

async function loadCharts() {

    try {

        const response =
            await fetch("/api/history");

        const data =
            await response.json();


        if (data.status !== "success") {
            return;
        }


        const flows = data.flows || [];


        // ====================================================
        // NETWORK PACKET TRAFFIC
        // ====================================================

        /*
            Group traffic into 5-second time buckets.

            Packets per flow =
                Forward packets + Backward packets
        */

        const packetBuckets = {};


        flows.forEach(flow => {

            if (!flow.timestamp) {
                return;
            }


            const timestamp =
                new Date(
                    flow.timestamp.replace(" ", "T")
                );


            if (isNaN(timestamp.getTime())) {
                return;
            }


            // Round timestamp down to nearest 5 seconds

            const seconds =
                timestamp.getSeconds();

            const bucketSeconds =
                Math.floor(seconds / 5) * 5;


            timestamp.setSeconds(
                bucketSeconds,
                0
            );


            const bucket =
                timestamp.toLocaleTimeString();


            const forwardPackets =
                Number(
                    flow.tot_fwd_pkts || 0
                );


            const backwardPackets =
                Number(
                    flow.tot_bwd_pkts || 0
                );


            const totalPackets =
                forwardPackets +
                backwardPackets;


            if (!packetBuckets[bucket]) {

                packetBuckets[bucket] = 0;

            }


            packetBuckets[bucket] +=
                totalPackets;

        });


        // Convert buckets into chart data

        const packetLabels =
            Object.keys(packetBuckets);


        const packetValues =
            Object.values(packetBuckets);


        const trafficCanvas =
            document.getElementById(
                "traffic-chart"
            );


        if (trafficCanvas) {

            if (trafficChart) {

                trafficChart.destroy();

            }


            trafficChart =
                new Chart(
                    trafficCanvas,
                    {

                        type: "line",

                        data: {

                            labels: packetLabels,

                            datasets: [

                                {

                                    label:
                                        "Packets",

                                    data:
                                        packetValues,

                                    tension:
                                        0.25,

                                    fill:
                                        false,

                                    pointRadius:
                                        3,

                                    pointHoverRadius:
                                        6

                                }

                            ]

                        },


                        options: {

                            responsive: true,

                            maintainAspectRatio: false,


                            interaction: {

                                intersect: false,

                                mode: "index"

                            },


                            scales: {

                                x: {

                                    title: {

                                        display: true,

                                        text: "Time"

                                    }

                                },


                                y: {

                                    beginAtZero: true,

                                    title: {

                                        display: true,

                                        text: "Packets"

                                    },

                                    ticks: {

                                        precision: 0

                                    }

                                }

                            },


                            plugins: {

                                legend: {

                                    display: true,

                                    position: "bottom"

                                },


                                tooltip: {

                                    callbacks: {

                                        label:
                                            function(context) {

                                                return (
                                                    "Packets: " +
                                                    context.parsed.y
                                                );

                                            }

                                    }

                                }

                            }

                        }

                    }
                );

        }


        // ====================================================
        // THREAT DISTRIBUTION
        // ====================================================

        let benign = 0;
        let portscan = 0;
        let ddos = 0;


        flows.forEach(flow => {

            const prediction =
                flow.prediction ||
                flow.Prediction ||
                "UNKNOWN";


            if (prediction === "BENIGN") {

                benign++;

            }

            else if (prediction === "PortScan") {

                portscan++;

            }

            else if (prediction === "DDoS") {

                ddos++;

            }

        });


        const threatCanvas =
            document.getElementById(
                "threat-chart"
            );


        if (threatCanvas) {

            if (threatChart) {

                threatChart.destroy();

            }


            threatChart =
                new Chart(
                    threatCanvas,
                    {

                        type: "bar",

                        data: {

                            labels: [
                                "BENIGN",
                                "PortScan",
                                "DDoS"
                            ],

                            datasets: [

                                {

                                    label:
                                        "Detected Flows",

                                    data: [
                                        benign,
                                        portscan,
                                        ddos
                                    ]

                                }

                            ]

                        },


                        options: {

                            responsive: true,

                            maintainAspectRatio: false,


                            scales: {

                                y: {

                                    beginAtZero: true,

                                    ticks: {

                                        precision: 0

                                    }

                                }

                            },


                            plugins: {

                                legend: {

                                    display: false

                                }

                            }

                        }

                    }
                );

        }

    }

    catch (error) {

        console.error(
            "Failed to load charts:",
            error
        );

    }

}

// ============================================================
// MONITORING HISTORY
// ============================================================

let historyFlows = [];

let currentHistoryFilter = "ALL";


// ------------------------------------------------------------
// LOAD HISTORY
// ------------------------------------------------------------

async function loadMonitoringHistory() {

    try {

        const response =
            await fetch("/api/history");

        const data =
            await response.json();


        if (data.status !== "success") {
            return;
        }


        historyFlows =
            data.flows || [];


        renderMonitoringHistory();

    }

    catch (error) {

        console.error(
            "Failed to load monitoring history:",
            error
        );

    }

}


// ------------------------------------------------------------
// RENDER HISTORY
// ------------------------------------------------------------

function renderMonitoringHistory() {

    const tableBody =
        document.getElementById(
            "history-table-body"
        );


    const countElement =
        document.getElementById(
            "history-count"
        );


    if (!tableBody) {
        return;
    }


    let filteredFlows =
        historyFlows;


    // --------------------------------------------------------
    // APPLY FILTER
    // --------------------------------------------------------

    if (currentHistoryFilter !== "ALL") {

        filteredFlows =
            historyFlows.filter(flow => {

                const prediction =
                    flow.prediction ||
                    flow.Prediction ||
                    "UNKNOWN";

                return (
                    prediction ===
                    currentHistoryFilter
                );

            });

    }


    // --------------------------------------------------------
    // UPDATE COUNT
    // --------------------------------------------------------

    if (countElement) {

        countElement.textContent =
            `Recorded Flows: ${filteredFlows.length}`;

    }


    // --------------------------------------------------------
    // EMPTY STATE
    // --------------------------------------------------------

    if (filteredFlows.length === 0) {

        tableBody.innerHTML = `

            <tr>

                <td
                    colspan="10"
                    style="text-align:center;"
                >
                    No flows found.
                </td>

            </tr>

        `;

        return;

    }


    // --------------------------------------------------------
    // RENDER ROWS
    // --------------------------------------------------------

    tableBody.innerHTML = "";


    filteredFlows.forEach(flow => {

        const row =
            document.createElement("tr");


        const prediction =
            flow.prediction ||
            flow.Prediction ||
            "UNKNOWN";


        let predictionClass = "";


        if (prediction === "BENIGN") {

            predictionClass =
                "prediction-benign";

        }

        else if (prediction === "PortScan") {

            predictionClass =
                "prediction-portscan";

        }

        else if (prediction === "DDoS") {

            predictionClass =
                "prediction-ddos";

        }


        row.classList.add("flow-row");


        // Make historical flow clickable too

        row.addEventListener(
            "click",
            () => openFlowModal(flow)
        );


        row.innerHTML = `

            <td>
                ${flow.timestamp || "-"}
            </td>

            <td>
                ${flow.src_ip || "-"}
            </td>

            <td>
                ${flow.dst_ip || "-"}
            </td>

            <td>
                ${flow.src_port || "-"}
            </td>

            <td>
                ${flow.dst_port || "-"}
            </td>

            <td>
                ${flow.protocol || "-"}
            </td>

            <td>
                ${flow.tot_fwd_pkts || 0}
            </td>

            <td>
                ${flow.tot_bwd_pkts || 0}
            </td>

            <td>
                ${flow.flow_duration || 0}
            </td>

            <td class="${predictionClass}">
                ${prediction}
            </td>

        `;


        tableBody.appendChild(row);

    });

}


// ------------------------------------------------------------
// FILTER HISTORY
// ------------------------------------------------------------

function filterHistory(
    filter,
    button
) {

    currentHistoryFilter =
        filter;


    // Remove active state

    document
        .querySelectorAll(
            ".history-filter"
        )
        .forEach(
            btn =>
                btn.classList.remove("active")
        );


    // Activate selected button

    if (button) {

        button.classList.add("active");

    }


    renderMonitoringHistory();

}