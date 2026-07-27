from __future__ import annotations

import os
import subprocess
import tempfile
from functools import lru_cache
from pathlib import Path
from typing import Any

import joblib
import numpy as np
import pandas as pd


PROJECT_ROOT = Path(__file__).resolve().parents[1]

MODEL_PATH = (
    PROJECT_ROOT
    / "models"
    / "cicids_intrusion_detector.joblib"
)

CICFLOWMETER_DIRECTORY = Path(
    r"C:\Users\salah\Desktop\CICFlowMeter"
)

GRADLE_WRAPPER = (
    CICFLOWMETER_DIRECTORY
    / "gradlew.bat"
)

TSHARK_PATH = Path(
    r"C:\Program Files\Wireshark\tshark.exe"
)


@lru_cache(maxsize=1)
def load_model_bundle() -> dict[str, Any]:
    if not MODEL_PATH.exists():
        raise FileNotFoundError(
            f"Modèle CICIDS2017 introuvable : {MODEL_PATH}"
        )

    bundle = joblib.load(MODEL_PATH)

    required_keys = {
        "model",
        "feature_names",
        "column_aliases",
        "non_feature_columns",
        "labels",
    }

    missing_keys = required_keys.difference(
        bundle.keys()
    )

    if missing_keys:
        raise ValueError(
            "Le modèle CICIDS2017 est incomplet. "
            f"Clés manquantes : {sorted(missing_keys)}"
        )

    return bundle


def convert_pcapng_to_pcap(
    input_path: Path,
    output_path: Path,
) -> Path:
    if not TSHARK_PATH.exists():
        raise FileNotFoundError(
            f"TShark est introuvable : {TSHARK_PATH}"
        )

    command = [
        str(TSHARK_PATH),
        "-r",
        str(input_path),
        "-F",
        "pcap",
        "-w",
        str(output_path),
    ]

    try:
        subprocess.run(
            command,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=True,
        )
    except subprocess.CalledProcessError as error:
        raise RuntimeError(
            "Impossible de convertir le fichier PCAPNG "
            f"en PCAP : {error.stderr.strip()}"
        ) from error

    if not output_path.exists():
        raise RuntimeError(
            "La conversion PCAPNG vers PCAP "
            "n'a produit aucun fichier."
        )

    return output_path


def create_gradle_init_script(
    script_path: Path,
) -> None:
    content = """
allprojects {
    afterEvaluate { currentProject ->
        def commandTask = currentProject.tasks.findByName("exeCMD")

        if (commandTask != null) {
            commandTask.args = [
                currentProject.findProperty("pcapInput"),
                currentProject.findProperty("flowOutput")
            ]
        }
    }
}
""".strip()

    script_path.write_text(
        content,
        encoding="utf-8",
    )


def generate_flow_csv(
    pcap_path: Path,
    output_directory: Path,
    init_script_path: Path,
) -> Path:
    if not CICFLOWMETER_DIRECTORY.exists():
        raise FileNotFoundError(
            "Le dossier CICFlowMeter est introuvable : "
            f"{CICFLOWMETER_DIRECTORY}"
        )

    if not GRADLE_WRAPPER.exists():
        raise FileNotFoundError(
            f"Gradle Wrapper est introuvable : {GRADLE_WRAPPER}"
        )

    output_directory.mkdir(
        parents=True,
        exist_ok=True,
    )

    create_gradle_init_script(
        init_script_path
    )

    command = [
        str(GRADLE_WRAPPER),
        "exeCMD",
        "--no-daemon",
        "-I",
        str(init_script_path),
        f"-PpcapInput={pcap_path}",
        f"-PflowOutput={output_directory}",
    ]

    jnetpcap_directory = (
        CICFLOWMETER_DIRECTORY
        / "jnetpcap"
        / "win"
        / "jnetpcap-1.4.r1425"
    )

    npcap_directory = Path(
        r"C:\Windows\System32\Npcap"
    )

    if not jnetpcap_directory.exists():
        raise FileNotFoundError(
            "Le dossier natif jNetPcap est introuvable : "
            f"{jnetpcap_directory}"
        )

    if not npcap_directory.exists():
        raise FileNotFoundError(
            f"Le dossier Npcap est introuvable : {npcap_directory}"
        )

    environment = os.environ.copy()

    existing_path = environment.get(
        "PATH",
        "",
    )

    environment["PATH"] = os.pathsep.join(
        [
            str(jnetpcap_directory),
            str(npcap_directory),
            existing_path,
        ]
    )

    try:
        result = subprocess.run(
            command,
            cwd=CICFLOWMETER_DIRECTORY,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=True,
            env=environment,
        )
    except subprocess.CalledProcessError as error:
        output = "\n".join(
            part
            for part in [
                error.stdout.strip(),
                error.stderr.strip(),
            ]
            if part
        )

        raise RuntimeError(
            "Erreur pendant l'extraction des flux "
            f"avec CICFlowMeter : {output}"
        ) from error

    csv_files = sorted(
        output_directory.glob("*.csv"),
        key=lambda path: path.stat().st_mtime,
        reverse=True,
    )

    if not csv_files:
        raise RuntimeError(
            "CICFlowMeter n'a généré aucun fichier CSV. "
            f"Sortie : {result.stdout.strip()}"
        )

    return csv_files[0]


def normalize_columns(
    dataframe: pd.DataFrame,
    aliases: dict[str, str],
) -> pd.DataFrame:
    dataframe = dataframe.copy()

    dataframe.columns = [
        str(column).strip()
        for column in dataframe.columns
    ]

    dataframe = dataframe.rename(
        columns=aliases
    )

    dataframe = dataframe.loc[
        :,
        ~dataframe.columns.duplicated(),
    ]

    return dataframe


def prepare_features(
    dataframe: pd.DataFrame,
    feature_names: list[str],
    aliases: dict[str, str],
    non_feature_columns: list[str],
) -> pd.DataFrame:
    dataframe = normalize_columns(
        dataframe,
        aliases,
    )

    dataframe = dataframe.drop(
        columns=[
            column
            for column in non_feature_columns
            if column in dataframe.columns
        ],
        errors="ignore",
    )

    for column in dataframe.columns:
        dataframe[column] = pd.to_numeric(
            dataframe[column],
            errors="coerce",
        )

    dataframe = dataframe.replace(
        [np.inf, -np.inf],
        np.nan,
    )

    for column in feature_names:
        if column not in dataframe.columns:
            dataframe[column] = 0.0

    dataframe = dataframe[
        feature_names
    ]

    dataframe = dataframe.fillna(0.0)

    return dataframe.astype(
        np.float32
    )


def create_flow_details(
    raw_dataframe: pd.DataFrame,
    predictions: np.ndarray,
    probabilities: np.ndarray,
    maximum_rows: int = 20,
) -> list[dict[str, Any]]:
    details: list[dict[str, Any]] = []

    indexes = np.argsort(
        probabilities
    )[::-1][:maximum_rows]

    for index in indexes:
        row = raw_dataframe.iloc[
            int(index)
        ]

        details.append(
            {
                "row_number": int(index) + 1,
                "source_ip": str(
                    row.get("Src IP", "")
                ),
                "source_port": str(
                    row.get("Src Port", "")
                ),
                "destination_ip": str(
                    row.get("Dst IP", "")
                ),
                "destination_port": str(
                    row.get("Dst Port", "")
                ),
                "protocol": str(
                    row.get("Protocol", "")
                ),
                "prediction": (
                    "Attaque"
                    if int(predictions[index]) == 1
                    else "Normal"
                ),
                "attack_probability": round(
                    float(probabilities[index]),
                    4,
                ),
            }
        )

    return details


def predict_flow_csv(
    csv_path: Path,
) -> dict[str, Any]:
    bundle = load_model_bundle()

    raw_dataframe = pd.read_csv(
        csv_path,
        low_memory=False,
    )

    if raw_dataframe.empty:
        raise ValueError(
            "Le fichier de flux généré "
            "par CICFlowMeter est vide."
        )

    model = bundle["model"]
    feature_names = bundle["feature_names"]
    aliases = bundle["column_aliases"]
    non_feature_columns = bundle[
        "non_feature_columns"
    ]

    features = prepare_features(
        raw_dataframe,
        feature_names,
        aliases,
        non_feature_columns,
    )

    predictions = model.predict(
        features
    )

    probabilities = model.predict_proba(
        features
    )[:, 1]

    total_flows = int(
        len(predictions)
    )

    attack_flows = int(
        np.sum(predictions == 1)
    )

    normal_flows = int(
        total_flows - attack_flows
    )

    attack_percentage = (
        attack_flows
        / total_flows
        * 100
        if total_flows
        else 0.0
    )

    maximum_probability = (
        float(np.max(probabilities))
        if len(probabilities)
        else 0.0
    )

    average_probability = (
        float(np.mean(probabilities))
        if len(probabilities)
        else 0.0
    )

    global_result = (
        "Attaque détectée"
        if attack_flows > 0
        else "Trafic normal"
    )

    return {
        "analysis_type": "machine_learning",
        "model": "CICIDS2017 Random Forest",
        "total_flows": total_flows,
        "normal_flows": normal_flows,
        "attack_flows": attack_flows,
        "attack_percentage": round(
            attack_percentage,
            2,
        ),
        "maximum_attack_probability": round(
            maximum_probability,
            4,
        ),
        "average_attack_probability": round(
            average_probability,
            4,
        ),
        "global_result": global_result,
        "top_suspicious_flows": create_flow_details(
            raw_dataframe,
            predictions,
            probabilities,
        ),
    }


def analyze_pcap_with_ml(
    capture_path: str | Path,
) -> dict[str, Any]:
    capture_path = Path(
        capture_path
    ).resolve()

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

    with tempfile.TemporaryDirectory(
        prefix="intrusion_detection_"
    ) as temporary_directory:
        temporary_directory_path = Path(
            temporary_directory
        )

        flow_output_directory = (
            temporary_directory_path
            / "flows"
        )

        init_script_path = (
            temporary_directory_path
            / "cicflowmeter.init.gradle"
        )

        if capture_path.suffix.lower() == ".pcapng":
            pcap_path = (
                temporary_directory_path
                / f"{capture_path.stem}.pcap"
            )

            convert_pcapng_to_pcap(
                capture_path,
                pcap_path,
            )
        else:
            pcap_path = capture_path

        flow_csv_path = generate_flow_csv(
            pcap_path,
            flow_output_directory,
            init_script_path,
        )

        return predict_flow_csv(
            flow_csv_path
        )
