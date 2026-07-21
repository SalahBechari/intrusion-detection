from __future__ import annotations

import csv
import subprocess
from collections import Counter
from pathlib import Path
from typing import Any


PROJECT_ROOT = Path(__file__).resolve().parents[1]

TSHARK_PATH = Path(
    r"C:\Program Files\Wireshark\tshark.exe"
)

ENCRYPTED_PROTOCOLS = {
    "TLSV1",
    "TLSV1.1",
    "TLSV1.2",
    "TLSV1.3",
    "SSL",
    "QUIC",
}

UNENCRYPTED_PROTOCOLS = {
    "HTTP",
    "FTP",
    "FTP-DATA",
    "TELNET",
}


def safe_integer(value: str | None) -> int:
    if value is None:
        return 0

    cleaned_value = value.strip()

    if not cleaned_value:
        return 0

    try:
        return int(cleaned_value, 0)
    except ValueError:
        return 0


def calculate_percentage(
    value: int,
    total: int,
) -> float:
    if total <= 0:
        return 0.0

    return round(
        value / total * 100,
        2,
    )


def build_security_summary(
    total_packets: int,
    protocol_counts: Counter[str],
    source_ip_counts: Counter[str],
    port_counts: Counter[str],
    syn_packets: int,
    ack_packets: int,
    reset_packets: int,
) -> dict[str, Any]:
    dominant_protocol = (
        protocol_counts.most_common(1)[0]
        if protocol_counts
        else ("UNKNOWN", 0)
    )

    most_active_source = (
        source_ip_counts.most_common(1)[0]
        if source_ip_counts
        else ("Inconnue", 0)
    )

    most_used_port = (
        port_counts.most_common(1)[0]
        if port_counts
        else ("Inconnu", 0)
    )

    encrypted_packets = sum(
        count
        for protocol, count in protocol_counts.items()
        if protocol.upper() in ENCRYPTED_PROTOCOLS
    )

    unencrypted_packets = sum(
        count
        for protocol, count in protocol_counts.items()
        if protocol.upper() in UNENCRYPTED_PROTOCOLS
    )

    dns_packets = sum(
        count
        for protocol, count in protocol_counts.items()
        if protocol.upper() == "DNS"
    )

    encrypted_percentage = calculate_percentage(
        encrypted_packets,
        total_packets,
    )

    unencrypted_percentage = calculate_percentage(
        unencrypted_packets,
        total_packets,
    )

    dns_percentage = calculate_percentage(
        dns_packets,
        total_packets,
    )

    syn_percentage = calculate_percentage(
        syn_packets,
        total_packets,
    )

    reset_percentage = calculate_percentage(
        reset_packets,
        total_packets,
    )

    indicators: list[str] = []
    score = 0

    if unencrypted_packets > 0:
        indicators.append(
            "Présence de protocoles non chiffrés "
            f"({unencrypted_packets} paquets)."
        )
        score += 1

    if unencrypted_percentage >= 10:
        indicators.append(
            "La proportion de trafic non chiffré "
            "est relativement importante."
        )
        score += 1

    if dns_percentage >= 20:
        indicators.append(
            "Le trafic DNS représente une part élevée "
            "de la capture."
        )
        score += 1

    if syn_percentage >= 30:
        indicators.append(
            "Un nombre important de paquets TCP SYN "
            "a été observé."
        )
        score += 2

    if (
        syn_packets > 100
        and ack_packets > 0
        and syn_packets > ack_packets * 2
    ):
        indicators.append(
            "Le nombre de paquets SYN est nettement "
            "supérieur au nombre de paquets ACK."
        )
        score += 2

    if reset_percentage >= 5:
        indicators.append(
            "Un taux notable de paquets TCP RST "
            "a été observé."
        )
        score += 1

    if encrypted_percentage < 25:
        indicators.append(
            "La proportion de trafic identifié comme "
            "chiffré est faible."
        )
        score += 1

    if not indicators:
        indicators.append(
            "Aucun indicateur descriptif majeur "
            "n’a été relevé dans cette capture."
        )

    if score >= 5:
        attention_level = "Élevé"
    elif score >= 2:
        attention_level = "Modéré"
    else:
        attention_level = "Faible"

    return {
        "analysis_type": "descriptive",
        "attention_level": attention_level,
        "attention_score": score,
        "dominant_protocol": {
            "protocol": dominant_protocol[0],
            "packets": dominant_protocol[1],
            "percentage": calculate_percentage(
                dominant_protocol[1],
                total_packets,
            ),
        },
        "most_active_source": {
            "ip": most_active_source[0],
            "packets": most_active_source[1],
            "percentage": calculate_percentage(
                most_active_source[1],
                total_packets,
            ),
        },
        "most_used_port": {
            "port": most_used_port[0],
            "occurrences": most_used_port[1],
        },
        "encrypted_traffic": {
            "packets": encrypted_packets,
            "percentage": encrypted_percentage,
        },
        "unencrypted_traffic": {
            "packets": unencrypted_packets,
            "percentage": unencrypted_percentage,
        },
        "tcp_flags": {
            "syn_packets": syn_packets,
            "ack_packets": ack_packets,
            "reset_packets": reset_packets,
            "syn_percentage": syn_percentage,
            "reset_percentage": reset_percentage,
        },
        "indicators": indicators,
        "warning": (
            "Ce niveau est descriptif et ne constitue pas "
            "une prédiction du modèle NSL-KDD."
        ),
    }


def analyze_pcap(
    capture_path: str | Path,
) -> dict[str, Any]:
    capture_path = Path(capture_path).resolve()

    if not TSHARK_PATH.exists():
        raise FileNotFoundError(
            f"TShark est introuvable : {TSHARK_PATH}"
        )

    if not capture_path.exists():
        raise FileNotFoundError(
            f"Capture introuvable : {capture_path}"
        )

    if capture_path.suffix.lower() not in {
        ".pcap",
        ".pcapng",
    }:
        raise ValueError(
            "Le fichier doit être au format "
            ".pcap ou .pcapng."
        )

    command = [
        str(TSHARK_PATH),
        "-r",
        str(capture_path),
        "-T",
        "fields",
        "-E",
        "header=y",
        "-E",
        "separator=,",
        "-E",
        "quote=d",
        "-E",
        "occurrence=f",
        "-e",
        "frame.number",
        "-e",
        "frame.len",
        "-e",
        "_ws.col.protocol",
        "-e",
        "ip.src",
        "-e",
        "ip.dst",
        "-e",
        "ipv6.src",
        "-e",
        "ipv6.dst",
        "-e",
        "tcp.srcport",
        "-e",
        "tcp.dstport",
        "-e",
        "udp.srcport",
        "-e",
        "udp.dstport",
        "-e",
        "tcp.flags.syn",
        "-e",
        "tcp.flags.ack",
        "-e",
        "tcp.flags.reset",
    ]

    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=True,
        )
    except subprocess.CalledProcessError as error:
        raise RuntimeError(
            "Erreur pendant l'analyse TShark : "
            f"{error.stderr.strip()}"
        ) from error

    rows = list(
        csv.DictReader(
            result.stdout.splitlines()
        )
    )

    protocol_counts: Counter[str] = Counter()
    source_ip_counts: Counter[str] = Counter()
    destination_ip_counts: Counter[str] = Counter()
    port_counts: Counter[str] = Counter()

    total_bytes = 0
    syn_packets = 0
    ack_packets = 0
    reset_packets = 0

    for row in rows:
        protocol = (
            row.get(
                "_ws.col.protocol",
                "",
            ).strip()
            or "UNKNOWN"
        )

        protocol_counts[protocol] += 1

        frame_length = safe_integer(
            row.get("frame.len")
        )

        total_bytes += frame_length

        source_ip = (
            row.get(
                "ip.src",
                "",
            ).strip()
            or row.get(
                "ipv6.src",
                "",
            ).strip()
        )

        destination_ip = (
            row.get(
                "ip.dst",
                "",
            ).strip()
            or row.get(
                "ipv6.dst",
                "",
            ).strip()
        )

        if source_ip:
            source_ip_counts[source_ip] += 1

        if destination_ip:
            destination_ip_counts[
                destination_ip
            ] += 1

        ports = [
            row.get(
                "tcp.srcport",
                "",
            ).strip(),
            row.get(
                "tcp.dstport",
                "",
            ).strip(),
            row.get(
                "udp.srcport",
                "",
            ).strip(),
            row.get(
                "udp.dstport",
                "",
            ).strip(),
        ]

        for port in ports:
            if port:
                port_counts[port] += 1

        if safe_integer(
            row.get("tcp.flags.syn")
        ) == 1:
            syn_packets += 1

        if safe_integer(
            row.get("tcp.flags.ack")
        ) == 1:
            ack_packets += 1

        if safe_integer(
            row.get("tcp.flags.reset")
        ) == 1:
            reset_packets += 1

    total_packets = len(rows)

    security_summary = build_security_summary(
        total_packets=total_packets,
        protocol_counts=protocol_counts,
        source_ip_counts=source_ip_counts,
        port_counts=port_counts,
        syn_packets=syn_packets,
        ack_packets=ack_packets,
        reset_packets=reset_packets,
    )

    return {
        "filename": capture_path.name,
        "total_packets": total_packets,
        "total_bytes": total_bytes,
        "total_megabytes": round(
            total_bytes / 1_000_000,
            4,
        ),
        "protocols": [
            {
                "protocol": protocol,
                "packets": count,
            }
            for protocol, count
            in protocol_counts.most_common()
        ],
        "top_source_ips": [
            {
                "ip": ip_address,
                "packets": count,
            }
            for ip_address, count
            in source_ip_counts.most_common(10)
        ],
        "top_destination_ips": [
            {
                "ip": ip_address,
                "packets": count,
            }
            for ip_address, count
            in destination_ip_counts.most_common(10)
        ],
        "top_ports": [
            {
                "port": port,
                "occurrences": count,
            }
            for port, count
            in port_counts.most_common(10)
        ],
        "security_summary": security_summary,
    }


def print_analysis(
    analysis: dict[str, Any],
) -> None:
    print(
        "Fichier :",
        analysis["filename"],
    )

    print(
        "Nombre de paquets :",
        analysis["total_packets"],
    )

    print(
        "Volume total :",
        analysis["total_megabytes"],
        "Mo",
    )

    print("\nProtocoles :")

    for item in analysis["protocols"]:
        print(
            f"- {item['protocol']} : "
            f"{item['packets']} paquets"
        )

    print("\nPrincipales IP sources :")

    for item in analysis["top_source_ips"]:
        print(
            f"- {item['ip']} : "
            f"{item['packets']} paquets"
        )

    print("\nPrincipales IP destinations :")

    for item in analysis[
        "top_destination_ips"
    ]:
        print(
            f"- {item['ip']} : "
            f"{item['packets']} paquets"
        )

    print("\nPorts les plus utilisés :")

    for item in analysis["top_ports"]:
        print(
            f"- Port {item['port']} : "
            f"{item['occurrences']} occurrences"
        )

    summary = analysis["security_summary"]

    print("\nRésumé descriptif de sécurité :")

    print(
        "- Niveau d’attention :",
        summary["attention_level"],
    )

    print(
        "- Protocole dominant :",
        summary["dominant_protocol"]["protocol"],
    )

    print(
        "- IP source la plus active :",
        summary["most_active_source"]["ip"],
    )

    print(
        "- Port le plus utilisé :",
        summary["most_used_port"]["port"],
    )

    print(
        "- Trafic chiffré :",
        summary["encrypted_traffic"]["percentage"],
        "%",
    )

    print("\nIndicateurs :")

    for indicator in summary["indicators"]:
        print(
            f"- {indicator}"
        )

    print(
        "\nAvertissement :",
        summary["warning"],
    )


if __name__ == "__main__":
    test_capture = (
        PROJECT_ROOT
        / "data"
        / "captures"
        / "test_capture.pcapng"
    )

    try:
        capture_analysis = analyze_pcap(
            test_capture
        )

        print_analysis(
            capture_analysis
        )

    except (
        FileNotFoundError,
        ValueError,
        RuntimeError,
    ) as error:
        print(
            f"Erreur : {error}"
        )