const form = document.getElementById("upload-form");
const fileInput = document.getElementById("csv-file");
const csvFileTitle = document.getElementById("csv-file-title");
const csvFileHelp = document.getElementById("csv-file-help");
const analyzeButton = document.getElementById("analyze-button");
const message = document.getElementById("message");
const resultsSection = document.getElementById("results-section");
const resultsBody = document.getElementById("results-body");
const searchInput = document.getElementById("search-input");
const dropZone = document.getElementById("drop-zone");
const downloadButton = document.getElementById("download-button");
const normalChartBar = document.getElementById("normal-chart-bar");
const attackChartBar = document.getElementById("attack-chart-bar");
const normalChartValue = document.getElementById("normal-chart-value");
const attackChartValue = document.getElementById("attack-chart-value");

const manualForm = document.getElementById("manual-form");
const manualResult = document.getElementById("manual-result");
const manualAnalyzeButton = document.getElementById(
    "manual-analyze-button"
);
const normalExampleButton = document.getElementById(
    "normal-example-button"
);
const attackExampleButton = document.getElementById(
    "attack-example-button"
);

const pcapForm = document.getElementById("pcap-form");
const pcapFileInput = document.getElementById("pcap-file");
const pcapFileTitle = document.getElementById("pcap-file-title");
const pcapFileHelp = document.getElementById("pcap-file-help");
const pcapAnalyzeButton = document.getElementById(
    "pcap-analyze-button"
);
const pcapDownloadButton = document.getElementById(
    "pcap-download-button"
);
const pcapMessage = document.getElementById("pcap-message");
const pcapResults = document.getElementById("pcap-results");
const pcapDropZone = document.getElementById("pcap-drop-zone");
const pcapTotalPackets = document.getElementById(
    "pcap-total-packets"
);
const pcapTotalVolume = document.getElementById(
    "pcap-total-volume"
);
const pcapProtocolCount = document.getElementById(
    "pcap-protocol-count"
);
const pcapPortCount = document.getElementById(
    "pcap-port-count"
);

const pcapMlSection = document.getElementById(
    "pcap-ml-section"
);
const pcapMlResult = document.getElementById(
    "pcap-ml-result"
);
const pcapMlTotalFlows = document.getElementById(
    "pcap-ml-total-flows"
);
const pcapMlNormalFlows = document.getElementById(
    "pcap-ml-normal-flows"
);
const pcapMlAttackFlows = document.getElementById(
    "pcap-ml-attack-flows"
);
const pcapMlAttackPercentage = document.getElementById(
    "pcap-ml-attack-percentage"
);
const pcapMlMaxProbability = document.getElementById(
    "pcap-ml-max-probability"
);
const pcapMlAverageProbability = document.getElementById(
    "pcap-ml-average-probability"
);
const pcapMlModel = document.getElementById(
    "pcap-ml-model"
);
const pcapMlFlowsBody = document.getElementById(
    "pcap-ml-flows-body"
);
const pcapProtocolsBody = document.getElementById(
    "pcap-protocols-body"
);
const pcapPortsBody = document.getElementById(
    "pcap-ports-body"
);
const pcapSourceIpsBody = document.getElementById(
    "pcap-source-ips-body"
);
const pcapDestinationIpsBody = document.getElementById(
    "pcap-destination-ips-body"
);
const protocolsChartCanvas = document.getElementById(
    "protocols-chart"
);
const portsChartCanvas = document.getElementById(
    "ports-chart"
);

const pcapAttentionLevel = document.getElementById(
    "pcap-attention-level"
);
const pcapDominantProtocol = document.getElementById(
    "pcap-dominant-protocol"
);
const pcapDominantProtocolDetails = document.getElementById(
    "pcap-dominant-protocol-details"
);
const pcapMostActiveSource = document.getElementById(
    "pcap-most-active-source"
);
const pcapMostActiveSourceDetails = document.getElementById(
    "pcap-most-active-source-details"
);
const pcapMostUsedPort = document.getElementById(
    "pcap-most-used-port"
);
const pcapMostUsedPortDetails = document.getElementById(
    "pcap-most-used-port-details"
);
const pcapEncryptedPercentage = document.getElementById(
    "pcap-encrypted-percentage"
);
const pcapEncryptedPackets = document.getElementById(
    "pcap-encrypted-packets"
);
const pcapSecurityIndicators = document.getElementById(
    "pcap-security-indicators"
);
const pcapSecurityWarning = document.getElementById(
    "pcap-security-warning"
);

let selectedManualExample = null;
let currentPredictions = [];
let currentPcapAnalysis = null;
let protocolsChart = null;
let portsChart = null;

function showMessage(text, type) {
    message.textContent = text;
    message.className = `message ${type}`;
}

function showPcapMessage(text, type) {
    pcapMessage.textContent = text;
    pcapMessage.className = `message ${type}`;
}

function formatError(detail) {
    if (typeof detail === "string") {
        return detail;
    }

    if (
        detail &&
        detail.message &&
        Array.isArray(detail.missing_columns)
    ) {
        return `${detail.message} Colonnes : ${detail.missing_columns.join(
            ", "
        )}`;
    }

    if (Array.isArray(detail)) {
        return detail
            .map((item) => item.msg)
            .join(" ");
    }

    return "La requête n’a pas pu être traitée.";
}

function escapeCsvValue(value) {
    const stringValue = String(value ?? "");

    if (
        stringValue.includes(",") ||
        stringValue.includes("\"") ||
        stringValue.includes("\n")
    ) {
        return `"${stringValue.replaceAll(
            "\"",
            "\"\""
        )}"`;
    }

    return stringValue;
}

function downloadCsvFile(content, filename) {
    const blob = new Blob(
        ["\uFEFF", content],
        {
            type: "text/csv;charset=utf-8;"
        }
    );

    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");

    link.href = url;
    link.download = filename;

    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);

    URL.revokeObjectURL(url);
}

function getRiskLevel(probability) {
    if (probability >= 0.7) {
        return {
            label: "Élevé",
            className: "badge-high"
        };
    }

    if (probability >= 0.1) {
        return {
            label: "Moyen",
            className: "badge-medium"
        };
    }

    return {
        label: "Faible",
        className: "badge-low"
    };
}

fileInput.addEventListener("change", () => {
    const file = fileInput.files[0];

    if (file) {
        csvFileTitle.textContent = file.name;
        csvFileHelp.textContent =
            "Fichier prêt pour l’analyse";
        dropZone.classList.add("file-selected");
    } else {
        csvFileTitle.textContent =
            "Cliquez pour sélectionner un fichier";
        csvFileHelp.textContent =
            "ou déposez votre fichier CSV ici";
        dropZone.classList.remove("file-selected");
    }
});

dropZone.addEventListener("dragover", (event) => {
    event.preventDefault();
    dropZone.classList.add("drag-over");
});

dropZone.addEventListener("dragleave", () => {
    dropZone.classList.remove("drag-over");
});

dropZone.addEventListener("drop", (event) => {
    event.preventDefault();
    dropZone.classList.remove("drag-over");

    const files = event.dataTransfer.files;

    if (files.length === 0) {
        return;
    }

    const droppedFile = files[0];

    if (!droppedFile.name.toLowerCase().endsWith(".csv")) {
        showMessage(
            "Le fichier déposé doit être au format CSV.",
            "error"
        );
        return;
    }

    const dataTransfer = new DataTransfer();

    dataTransfer.items.add(droppedFile);
    fileInput.files = dataTransfer.files;

    csvFileTitle.textContent = droppedFile.name;
    csvFileHelp.textContent =
        "Fichier prêt pour l’analyse";
    dropZone.classList.add("file-selected");
});

form.addEventListener("submit", async (event) => {
    event.preventDefault();

    const file = fileInput.files[0];

    if (!file) {
        showMessage(
            "Veuillez sélectionner un fichier CSV.",
            "error"
        );
        return;
    }

    if (!file.name.toLowerCase().endsWith(".csv")) {
        showMessage(
            "Le fichier sélectionné doit être au format CSV.",
            "error"
        );
        return;
    }

    const formData = new FormData();
    formData.append("file", file);

    analyzeButton.disabled = true;
    analyzeButton.textContent = "Analyse en cours...";
    message.classList.add("hidden");
    resultsSection.classList.add("hidden");
    downloadButton.disabled = true;

    try {
        const response = await fetch(
            "/predict-csv",
            {
                method: "POST",
                body: formData
            }
        );

        const data = await response.json();

        if (!response.ok) {
            throw new Error(
                formatError(data.detail)
            );
        }

        displayResults(data);

        showMessage(
            "Analyse terminée avec succès.",
            "success"
        );
    } catch (error) {
        showMessage(
            error.message ||
            "Une erreur est survenue.",
            "error"
        );
    } finally {
        analyzeButton.disabled = false;
        analyzeButton.textContent =
            "Analyser les connexions";
    }
});

function displayResults(data) {
    document.getElementById(
        "total-connections"
    ).textContent = data.total_connections;

    document.getElementById(
        "normal-connections"
    ).textContent = data.normal_connections;

    document.getElementById(
        "attack-connections"
    ).textContent = data.attack_connections;

    const attackRate =
        data.total_connections === 0
            ? 0
            : (
                data.attack_connections /
                data.total_connections
            ) * 100;

    document.getElementById(
        "attack-rate"
    ).textContent = `${attackRate.toFixed(1)} %`;

    currentPredictions = data.predictions;

    updateChart(data);
    renderTable(currentPredictions);

    downloadButton.disabled = false;
    resultsSection.classList.remove("hidden");

    resultsSection.scrollIntoView({
        behavior: "smooth"
    });
}

function updateChart(data) {
    const total = data.total_connections;

    const normalPercentage =
        total === 0
            ? 0
            : (
                data.normal_connections /
                total
            ) * 100;

    const attackPercentage =
        total === 0
            ? 0
            : (
                data.attack_connections /
                total
            ) * 100;

    normalChartValue.textContent =
        `${data.normal_connections} ` +
        `(${normalPercentage.toFixed(1)} %)`;

    attackChartValue.textContent =
        `${data.attack_connections} ` +
        `(${attackPercentage.toFixed(1)} %)`;

    normalChartBar.style.width =
        `${normalPercentage}%`;

    attackChartBar.style.width =
        `${attackPercentage}%`;
}

function renderTable(predictions) {
    resultsBody.innerHTML = "";

    if (predictions.length === 0) {
        const row = document.createElement("tr");

        row.innerHTML = `
            <td colspan="4">
                Aucun résultat trouvé.
            </td>
        `;

        resultsBody.appendChild(row);
        return;
    }

    predictions.forEach((item) => {
        const row = document.createElement("tr");

        const probabilityPercent =
            item.attack_probability * 100;

        const risk = getRiskLevel(
            item.attack_probability
        );

        const badgeClass =
            item.prediction === "Attaque"
                ? "badge-attack"
                : "badge-normal";

        row.innerHTML = `
            <td>${item.row_number}</td>
            <td>
                <span class="badge ${badgeClass}">
                    ${item.prediction}
                </span>
            </td>
            <td>
                ${probabilityPercent.toFixed(2)} %
            </td>
            <td>
                <span class="badge ${risk.className}">
                    ${risk.label}
                </span>
            </td>
        `;

        resultsBody.appendChild(row);
    });
}

searchInput.addEventListener("input", () => {
    const value = searchInput.value
        .trim()
        .toLowerCase();

    const filteredPredictions =
        currentPredictions.filter((item) => {
            return (
                String(item.row_number).includes(value) ||
                item.prediction
                    .toLowerCase()
                    .includes(value)
            );
        });

    renderTable(filteredPredictions);
});

downloadButton.addEventListener("click", () => {
    if (currentPredictions.length === 0) {
        showMessage(
            "Aucun résultat à télécharger.",
            "error"
        );
        return;
    }

    const csvContent = createResultsCsv(
        currentPredictions
    );

    downloadCsvFile(
        csvContent,
        "intrusion_detection_results.csv"
    );
});

function createResultsCsv(predictions) {
    const headers = [
        "row_number",
        "prediction",
        "attack_probability",
        "attack_probability_percent",
        "risk_level"
    ];

    const rows = predictions.map((item) => {
        const risk = getRiskLevel(
            item.attack_probability
        );

        return [
            item.row_number,
            item.prediction,
            item.attack_probability,
            (
                item.attack_probability * 100
            ).toFixed(2),
            risk.label
        ];
    });

    return [
        headers,
        ...rows
    ]
        .map((row) => {
            return row
                .map(escapeCsvValue)
                .join(",");
        })
        .join("\n");
}

manualForm.addEventListener(
    "submit",
    async (event) => {
        event.preventDefault();

        manualAnalyzeButton.disabled = true;
        manualAnalyzeButton.textContent =
            "Analyse en cours...";
        manualResult.className =
            "manual-result hidden";

        const defaultConnectionData = {
            land: 0,
            wrong_fragment: 0,
            urgent: 0,
            hot: 0,
            num_failed_logins: 0,
            logged_in: 1,
            num_compromised: 0,
            root_shell: 0,
            su_attempted: 0,
            num_root: 0,
            num_file_creations: 0,
            num_shells: 0,
            num_access_files: 0,
            num_outbound_cmds: 0,
            is_host_login: 0,
            is_guest_login: 0,
            count: 8,
            srv_count: 8,
            serror_rate: 0,
            srv_serror_rate: 0,
            rerror_rate: 0,
            srv_rerror_rate: 0,
            same_srv_rate: 1,
            diff_srv_rate: 0,
            srv_diff_host_rate: 0,
            dst_host_count: 9,
            dst_host_srv_count: 9,
            dst_host_same_srv_rate: 1,
            dst_host_diff_srv_rate: 0,
            dst_host_same_src_port_rate: 0.11,
            dst_host_srv_diff_host_rate: 0,
            dst_host_serror_rate: 0,
            dst_host_srv_serror_rate: 0,
            dst_host_rerror_rate: 0,
            dst_host_srv_rerror_rate: 0
        };

        const connectionData = {
            ...defaultConnectionData,
            ...(selectedManualExample || {}),
            duration: Number(
                document.getElementById(
                    "duration"
                ).value
            ),
            protocol_type:
                document.getElementById(
                    "protocol_type"
                ).value,
            service:
                document.getElementById(
                    "service"
                ).value.trim(),
            flag:
                document.getElementById(
                    "flag"
                ).value.trim(),
            src_bytes: Number(
                document.getElementById(
                    "src_bytes"
                ).value
            ),
            dst_bytes: Number(
                document.getElementById(
                    "dst_bytes"
                ).value
            )
        };

        try {
            const response = await fetch(
                "/predict",
                {
                    method: "POST",
                    headers: {
                        "Content-Type":
                            "application/json"
                    },
                    body: JSON.stringify(
                        connectionData
                    )
                }
            );

            const data = await response.json();

            if (!response.ok) {
                throw new Error(
                    formatError(data.detail)
                );
            }

            const probability =
                data.attack_probability * 100;

            const resultClass =
                data.prediction === "Attaque"
                    ? "error"
                    : "success";

            const risk = getRiskLevel(
                data.attack_probability
            );

            manualResult.className =
                `manual-result ${resultClass}`;

            manualResult.innerHTML = `
                <strong>${data.prediction}</strong>
                <p>
                    Probabilité d’attaque :
                    ${probability.toFixed(2)} %
                </p>
                <p>
                    Niveau de risque :
                    ${risk.label}
                </p>
            `;
        } catch (error) {
            manualResult.className =
                "manual-result error";

            manualResult.textContent =
                error.message ||
                "Une erreur est survenue.";
        } finally {
            manualAnalyzeButton.disabled = false;
            manualAnalyzeButton.textContent =
                "Analyser cette connexion";
        }
    }
);

normalExampleButton.addEventListener(
    "click",
    async () => {
        await loadManualExample("normal");
    }
);

attackExampleButton.addEventListener(
    "click",
    async () => {
        await loadManualExample("attack");
    }
);

async function loadManualExample(exampleType) {
    try {
        const response = await fetch(
            `/examples/${exampleType}`
        );

        const data = await response.json();

        if (!response.ok) {
            throw new Error(
                data.detail ||
                "Impossible de charger l’exemple."
            );
        }

        selectedManualExample = data;

        document.getElementById(
            "duration"
        ).value = data.duration;

        document.getElementById(
            "protocol_type"
        ).value = data.protocol_type;

        document.getElementById(
            "service"
        ).value = data.service;

        document.getElementById(
            "flag"
        ).value = data.flag;

        document.getElementById(
            "src_bytes"
        ).value = data.src_bytes;

        document.getElementById(
            "dst_bytes"
        ).value = data.dst_bytes;

        manualResult.className =
            "manual-result hidden";
    } catch (error) {
        manualResult.className =
            "manual-result error";

        manualResult.textContent =
            error.message;
    }
}

pcapFileInput.addEventListener("change", () => {
    const file = pcapFileInput.files[0];

    if (file) {
        pcapFileTitle.textContent = file.name;
        pcapFileHelp.textContent =
            "Fichier prêt pour l’analyse";
        pcapDropZone.classList.add(
            "file-selected"
        );
    } else {
        pcapFileTitle.textContent =
            "Sélectionner une capture Wireshark";
        pcapFileHelp.textContent =
            "Formats acceptés : .pcap et .pcapng";
        pcapDropZone.classList.remove(
            "file-selected"
        );
    }

    currentPcapAnalysis = null;
    pcapDownloadButton.disabled = true;
});

pcapDropZone.addEventListener(
    "dragover",
    (event) => {
        event.preventDefault();
        pcapDropZone.classList.add(
            "drag-over"
        );
    }
);

pcapDropZone.addEventListener(
    "dragleave",
    () => {
        pcapDropZone.classList.remove(
            "drag-over"
        );
    }
);

pcapDropZone.addEventListener(
    "drop",
    (event) => {
        event.preventDefault();

        pcapDropZone.classList.remove(
            "drag-over"
        );

        const files = event.dataTransfer.files;

        if (files.length === 0) {
            return;
        }

        const droppedFile = files[0];
        const filename =
            droppedFile.name.toLowerCase();

        if (
            !filename.endsWith(".pcap") &&
            !filename.endsWith(".pcapng")
        ) {
            showPcapMessage(
                "Le fichier doit être au format PCAP ou PCAPNG.",
                "error"
            );
            return;
        }

        const dataTransfer = new DataTransfer();

        dataTransfer.items.add(droppedFile);
        pcapFileInput.files =
            dataTransfer.files;

        pcapFileTitle.textContent =
            droppedFile.name;

        pcapFileHelp.textContent =
            "Fichier prêt pour l’analyse";

        pcapDropZone.classList.add(
            "file-selected"
        );

        currentPcapAnalysis = null;
        pcapDownloadButton.disabled = true;
    }
);

pcapForm.addEventListener(
    "submit",
    async (event) => {
        event.preventDefault();

        const file =
            pcapFileInput.files[0];

        if (!file) {
            showPcapMessage(
                "Veuillez sélectionner une capture Wireshark.",
                "error"
            );
            return;
        }

        const filename =
            file.name.toLowerCase();

        if (
            !filename.endsWith(".pcap") &&
            !filename.endsWith(".pcapng")
        ) {
            showPcapMessage(
                "Le fichier doit être au format PCAP ou PCAPNG.",
                "error"
            );
            return;
        }

        const formData = new FormData();
        formData.append("file", file);

        pcapAnalyzeButton.disabled = true;
        pcapAnalyzeButton.textContent =
            "Analyse en cours...";
        pcapDownloadButton.disabled = true;
        currentPcapAnalysis = null;
        pcapResults.classList.add("hidden");

        showPcapMessage(
            "Analyse de la capture en cours...",
            "loading"
        );

        try {
            const response = await fetch(
                "/analyze-pcap",
                {
                    method: "POST",
                    body: formData
                }
            );

            const data = await response.json();

            if (!response.ok) {
                throw new Error(
                    formatError(data.detail)
                );
            }

            displayPcapResults(data);

            showPcapMessage(
                "Capture analysée avec succès.",
                "success"
            );
        } catch (error) {
            showPcapMessage(
                error.message ||
                "Une erreur est survenue pendant l’analyse.",
                "error"
            );
        } finally {
            pcapAnalyzeButton.disabled = false;
            pcapAnalyzeButton.textContent =
                "Analyser la capture";
        }
    }
);

function displayPcapResults(data) {
    currentPcapAnalysis = data;

    pcapTotalPackets.textContent =
        Number(
            data.total_packets
        ).toLocaleString("fr-FR");

    pcapTotalVolume.textContent =
        `${Number(
            data.total_megabytes
        ).toFixed(4)} Mo`;

    pcapProtocolCount.textContent =
        data.protocols.length;

    pcapPortCount.textContent =
        data.top_ports.length;

    renderSecuritySummary(
        data.security_summary
    );

    renderMachineLearningResults(
        data.machine_learning
    );

    renderPcapTable(
        pcapProtocolsBody,
        data.protocols,
        "protocol",
        "packets"
    );

    renderPcapTable(
        pcapPortsBody,
        data.top_ports,
        "port",
        "occurrences"
    );

    renderPcapTable(
        pcapSourceIpsBody,
        data.top_source_ips,
        "ip",
        "packets"
    );

    renderPcapTable(
        pcapDestinationIpsBody,
        data.top_destination_ips,
        "ip",
        "packets"
    );

    pcapResults.classList.remove("hidden");

    renderProtocolsChart(
        data.protocols
    );

    renderPortsChart(
        data.top_ports
    );

    pcapDownloadButton.disabled = false;

    pcapResults.scrollIntoView({
        behavior: "smooth",
        block: "start"
    });
}

function renderMachineLearningResults(analysis) {
    if (!analysis) {
        pcapMlSection.classList.add("hidden");
        return;
    }

    pcapMlTotalFlows.textContent =
        Number(
            analysis.total_flows
        ).toLocaleString("fr-FR");

    pcapMlNormalFlows.textContent =
        Number(
            analysis.normal_flows
        ).toLocaleString("fr-FR");

    pcapMlAttackFlows.textContent =
        Number(
            analysis.attack_flows
        ).toLocaleString("fr-FR");

    pcapMlAttackPercentage.textContent =
        `${Number(
            analysis.attack_percentage
        ).toFixed(2)} %`;

    pcapMlMaxProbability.textContent =
        `${(
            Number(
                analysis.maximum_attack_probability
            ) * 100
        ).toFixed(2)} %`;

    pcapMlAverageProbability.textContent =
        `${(
            Number(
                analysis.average_attack_probability
            ) * 100
        ).toFixed(2)} %`;

    pcapMlModel.textContent =
        analysis.model || "CICIDS2017 Random Forest";

    pcapMlResult.textContent =
        analysis.global_result;

    const attackDetected =
        Number(analysis.attack_flows) > 0;

    pcapMlResult.className =
        attackDetected
            ? "ml-result-badge ml-result-attack"
            : "ml-result-badge ml-result-normal";

    renderMachineLearningFlows(
        analysis.top_suspicious_flows || []
    );

    pcapMlSection.classList.remove("hidden");
}

function renderMachineLearningFlows(flows) {
    pcapMlFlowsBody.innerHTML = "";

    if (!flows || flows.length === 0) {
        const row = document.createElement("tr");

        row.innerHTML = `
            <td colspan="8">
                Aucun flux disponible.
            </td>
        `;

        pcapMlFlowsBody.appendChild(row);
        return;
    }

    flows.forEach((flow) => {
        const row = document.createElement("tr");

        const badgeClass =
            flow.prediction === "Attaque"
                ? "badge-attack"
                : "badge-normal";

        const probability =
            Number(flow.attack_probability) * 100;

        row.innerHTML = `
            <td>${flow.row_number}</td>
            <td>${flow.source_ip || "-"}</td>
            <td>${flow.source_port || "-"}</td>
            <td>${flow.destination_ip || "-"}</td>
            <td>${flow.destination_port || "-"}</td>
            <td>${flow.protocol || "-"}</td>
            <td>
                <span class="badge ${badgeClass}">
                    ${flow.prediction}
                </span>
            </td>
            <td>${probability.toFixed(2)} %</td>
        `;

        pcapMlFlowsBody.appendChild(row);
    });
}

function renderSecuritySummary(summary) {
    if (!summary) {
        return;
    }

    pcapAttentionLevel.textContent =
        summary.attention_level;

    pcapAttentionLevel.className =
        `attention-badge ${getAttentionClass(
            summary.attention_level
        )}`;

    pcapDominantProtocol.textContent =
        summary.dominant_protocol.protocol;

    pcapDominantProtocolDetails.textContent =
        `${Number(
            summary.dominant_protocol.packets
        ).toLocaleString("fr-FR")} paquets ` +
        `(${Number(
            summary.dominant_protocol.percentage
        ).toFixed(2)} %)`;

    pcapMostActiveSource.textContent =
        summary.most_active_source.ip;

    pcapMostActiveSourceDetails.textContent =
        `${Number(
            summary.most_active_source.packets
        ).toLocaleString("fr-FR")} paquets ` +
        `(${Number(
            summary.most_active_source.percentage
        ).toFixed(2)} %)`;

    pcapMostUsedPort.textContent =
        summary.most_used_port.port;

    pcapMostUsedPortDetails.textContent =
        `${Number(
            summary.most_used_port.occurrences
        ).toLocaleString("fr-FR")} occurrences`;

    pcapEncryptedPercentage.textContent =
        `${Number(
            summary.encrypted_traffic.percentage
        ).toFixed(2)} %`;

    pcapEncryptedPackets.textContent =
        `${Number(
            summary.encrypted_traffic.packets
        ).toLocaleString("fr-FR")} paquets`;

    pcapSecurityIndicators.innerHTML = "";

    summary.indicators.forEach((indicator) => {
        const item =
            document.createElement("li");

        item.textContent = indicator;

        pcapSecurityIndicators.appendChild(
            item
        );
    });

    pcapSecurityWarning.textContent =
        summary.warning;
}

function getAttentionClass(level) {
    const normalizedLevel = String(level)
        .trim()
        .toLowerCase();

    if (
        normalizedLevel === "élevé" ||
        normalizedLevel === "eleve"
    ) {
        return "attention-high";
    }

    if (
        normalizedLevel === "modéré" ||
        normalizedLevel === "modere"
    ) {
        return "attention-medium";
    }

    return "attention-low";
}

function renderPcapTable(
    tableBody,
    items,
    firstKey,
    secondKey
) {
    tableBody.innerHTML = "";

    if (!items || items.length === 0) {
        const row =
            document.createElement("tr");

        row.innerHTML = `
            <td colspan="2">
                Aucune donnée trouvée.
            </td>
        `;

        tableBody.appendChild(row);
        return;
    }

    items.forEach((item) => {
        const row =
            document.createElement("tr");

        const firstCell =
            document.createElement("td");

        const secondCell =
            document.createElement("td");

        firstCell.textContent =
            item[firstKey];

        secondCell.textContent =
            Number(
                item[secondKey]
            ).toLocaleString("fr-FR");

        row.appendChild(firstCell);
        row.appendChild(secondCell);

        tableBody.appendChild(row);
    });
}

function renderProtocolsChart(protocols) {
    if (
        typeof Chart === "undefined" ||
        !protocolsChartCanvas
    ) {
        return;
    }

    if (protocolsChart) {
        protocolsChart.destroy();
    }

    const labels = protocols.map(
        (item) => item.protocol
    );

    const values = protocols.map(
        (item) => item.packets
    );

    protocolsChart = new Chart(
        protocolsChartCanvas,
        {
            type: "doughnut",
            data: {
                labels,
                datasets: [
                    {
                        data: values,
                        backgroundColor: [
                            "#173f70",
                            "#2c6eaa",
                            "#4a90c2",
                            "#69a9d2",
                            "#16845b",
                            "#48a57d",
                            "#b77717",
                            "#d39a42",
                            "#c83c4d",
                            "#8d5bb7"
                        ],
                        borderColor: "#ffffff",
                        borderWidth: 2
                    }
                ]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                cutout: "62%",
                plugins: {
                    legend: {
                        position: "bottom",
                        labels: {
                            usePointStyle: true,
                            padding: 16
                        }
                    },
                    tooltip: {
                        callbacks: {
                            label(context) {
                                const value =
                                    Number(context.raw);

                                const total =
                                    context.dataset.data.reduce(
                                        (sum, item) =>
                                            sum + Number(item),
                                        0
                                    );

                                const percentage =
                                    total === 0
                                        ? 0
                                        : (
                                            value /
                                            total
                                        ) * 100;

                                return (
                                    `${context.label} : ` +
                                    `${value.toLocaleString(
                                        "fr-FR"
                                    )} paquets ` +
                                    `(${percentage.toFixed(
                                        1
                                    )} %)`
                                );
                            }
                        }
                    }
                }
            }
        }
    );
}

function renderPortsChart(ports) {
    if (
        typeof Chart === "undefined" ||
        !portsChartCanvas
    ) {
        return;
    }

    if (portsChart) {
        portsChart.destroy();
    }

    const labels = ports.map(
        (item) => `Port ${item.port}`
    );

    const values = ports.map(
        (item) => item.occurrences
    );

    portsChart = new Chart(
        portsChartCanvas,
        {
            type: "bar",
            data: {
                labels,
                datasets: [
                    {
                        label: "Occurrences",
                        data: values,
                        backgroundColor: "#173f70",
                        borderRadius: 6,
                        borderSkipped: false
                    }
                ]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                indexAxis: "y",
                scales: {
                    x: {
                        beginAtZero: true,
                        ticks: {
                            precision: 0
                        },
                        grid: {
                            color:
                                "rgba(104, 118, 138, 0.12)"
                        }
                    },
                    y: {
                        grid: {
                            display: false
                        }
                    }
                },
                plugins: {
                    legend: {
                        display: false
                    },
                    tooltip: {
                        callbacks: {
                            label(context) {
                                return (
                                    `${Number(
                                        context.raw
                                    ).toLocaleString(
                                        "fr-FR"
                                    )} occurrences`
                                );
                            }
                        }
                    }
                }
            }
        }
    );
}

pcapDownloadButton.addEventListener(
    "click",
    () => {
        if (!currentPcapAnalysis) {
            showPcapMessage(
                "Aucune analyse PCAP à télécharger.",
                "error"
            );
            return;
        }

        const csvContent =
            createPcapAnalysisCsv(
                currentPcapAnalysis
            );

        const originalName =
            pcapFileInput.files[0]
                ? pcapFileInput.files[0].name
                : currentPcapAnalysis.filename;

        const baseName =
            originalName.replace(
                /\.(pcapng|pcap)$/i,
                ""
            );

        downloadCsvFile(
            csvContent,
            `${baseName}_analyse.csv`
        );
    }
);

function createPcapAnalysisCsv(data) {
    const rows = [
        [
            "categorie",
            "element",
            "valeur"
        ],
        [
            "resume",
            "fichier",
            data.filename
        ],
        [
            "resume",
            "nombre_total_paquets",
            data.total_packets
        ],
        [
            "resume",
            "volume_total_octets",
            data.total_bytes
        ],
        [
            "resume",
            "volume_total_megabytes",
            data.total_megabytes
        ],
        [
            "resume",
            "nombre_protocoles",
            data.protocols.length
        ],
        [
            "resume",
            "nombre_ports_principaux",
            data.top_ports.length
        ]
    ];

    if (data.machine_learning) {
        const ml =
            data.machine_learning;

        rows.push(
            [
                "machine_learning",
                "modele",
                ml.model
            ],
            [
                "machine_learning",
                "resultat_global",
                ml.global_result
            ],
            [
                "machine_learning",
                "nombre_total_flux",
                ml.total_flows
            ],
            [
                "machine_learning",
                "flux_normaux",
                ml.normal_flows
            ],
            [
                "machine_learning",
                "flux_suspects",
                ml.attack_flows
            ],
            [
                "machine_learning",
                "pourcentage_suspect",
                ml.attack_percentage
            ],
            [
                "machine_learning",
                "probabilite_maximale",
                ml.maximum_attack_probability
            ],
            [
                "machine_learning",
                "probabilite_moyenne",
                ml.average_attack_probability
            ]
        );

        (
            ml.top_suspicious_flows || []
        ).forEach((flow) => {
            rows.push([
                "flux_machine_learning",
                `ligne_${flow.row_number}`,
                [
                    flow.source_ip,
                    flow.source_port,
                    flow.destination_ip,
                    flow.destination_port,
                    flow.protocol,
                    flow.prediction,
                    flow.attack_probability
                ].join(" | ")
            ]);
        });
    }

    if (data.security_summary) {
        const summary =
            data.security_summary;

        rows.push(
            [
                "securite",
                "niveau_attention",
                summary.attention_level
            ],
            [
                "securite",
                "score_attention",
                summary.attention_score
            ],
            [
                "securite",
                "protocole_dominant",
                summary.dominant_protocol.protocol
            ],
            [
                "securite",
                "paquets_protocole_dominant",
                summary.dominant_protocol.packets
            ],
            [
                "securite",
                "pourcentage_protocole_dominant",
                summary.dominant_protocol.percentage
            ],
            [
                "securite",
                "ip_source_plus_active",
                summary.most_active_source.ip
            ],
            [
                "securite",
                "paquets_ip_source_plus_active",
                summary.most_active_source.packets
            ],
            [
                "securite",
                "pourcentage_ip_source_plus_active",
                summary.most_active_source.percentage
            ],
            [
                "securite",
                "port_plus_utilise",
                summary.most_used_port.port
            ],
            [
                "securite",
                "occurrences_port_plus_utilise",
                summary.most_used_port.occurrences
            ],
            [
                "securite",
                "trafic_chiffre_paquets",
                summary.encrypted_traffic.packets
            ],
            [
                "securite",
                "trafic_chiffre_pourcentage",
                summary.encrypted_traffic.percentage
            ],
            [
                "securite",
                "trafic_non_chiffre_paquets",
                summary.unencrypted_traffic.packets
            ],
            [
                "securite",
                "trafic_non_chiffre_pourcentage",
                summary.unencrypted_traffic.percentage
            ],
            [
                "securite",
                "paquets_syn",
                summary.tcp_flags.syn_packets
            ],
            [
                "securite",
                "paquets_ack",
                summary.tcp_flags.ack_packets
            ],
            [
                "securite",
                "paquets_reset",
                summary.tcp_flags.reset_packets
            ],
            [
                "securite",
                "pourcentage_syn",
                summary.tcp_flags.syn_percentage
            ],
            [
                "securite",
                "pourcentage_reset",
                summary.tcp_flags.reset_percentage
            ],
            [
                "securite",
                "avertissement",
                summary.warning
            ]
        );

        summary.indicators.forEach(
            (indicator, index) => {
                rows.push([
                    "indicateur_securite",
                    `indicateur_${index + 1}`,
                    indicator
                ]);
            }
        );
    }

    data.protocols.forEach((item) => {
        rows.push([
            "protocole",
            item.protocol,
            item.packets
        ]);
    });

    data.top_ports.forEach((item) => {
        rows.push([
            "port",
            item.port,
            item.occurrences
        ]);
    });

    data.top_source_ips.forEach((item) => {
        rows.push([
            "ip_source",
            item.ip,
            item.packets
        ]);
    });

    data.top_destination_ips.forEach((item) => {
        rows.push([
            "ip_destination",
            item.ip,
            item.packets
        ]);
    });

    return rows
        .map((row) => {
            return row
                .map(escapeCsvValue)
                .join(",");
        })
        .join("\n");
}