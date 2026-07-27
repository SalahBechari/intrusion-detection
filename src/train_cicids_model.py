from pathlib import Path
import json

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)
from sklearn.model_selection import train_test_split


PROJECT_ROOT = Path(__file__).resolve().parent.parent

DATA_DIRECTORY = (
    PROJECT_ROOT
    / "data"
    / "cicids2017"
    / "extracted"
    / "MachineLearningCVE"
)

MODEL_PATH = PROJECT_ROOT / "models" / "cicids_intrusion_detector.joblib"
REPORT_PATH = PROJECT_ROOT / "reports" / "cicids_metrics.json"

CHUNK_SIZE = 50_000
MAX_NORMAL_ROWS_PER_FILE = 25_000
MAX_ATTACK_ROWS_PER_FILE = 25_000
RANDOM_STATE = 42

COLUMN_ALIASES = {
    "Dst Port": "Destination Port",
    "Total Fwd Packet": "Total Fwd Packets",
    "Total Bwd packets": "Total Backward Packets",
    "Total Length of Fwd Packet": "Total Length of Fwd Packets",
    "Total Length of Bwd Packet": "Total Length of Bwd Packets",
    "Packet Length Min": "Min Packet Length",
    "Packet Length Max": "Max Packet Length",
    "Fwd Segment Size Avg": "Avg Fwd Segment Size",
    "Bwd Segment Size Avg": "Avg Bwd Segment Size",
    "Fwd Bytes/Bulk Avg": "Fwd Avg Bytes/Bulk",
    "Fwd Packet/Bulk Avg": "Fwd Avg Packets/Bulk",
    "Fwd Bulk Rate Avg": "Fwd Avg Bulk Rate",
    "Bwd Bytes/Bulk Avg": "Bwd Avg Bytes/Bulk",
    "Bwd Packet/Bulk Avg": "Bwd Avg Packets/Bulk",
    "Bwd Bulk Rate Avg": "Bwd Avg Bulk Rate",
    "FWD Init Win Bytes": "Init_Win_bytes_forward",
    "Bwd Init Win Bytes": "Init_Win_bytes_backward",
    "Fwd Act Data Pkts": "act_data_pkt_fwd",
    "Fwd Seg Size Min": "min_seg_size_forward",
    "CWR Flag Count": "CWE Flag Count",
}

NON_FEATURE_COLUMNS = {
    "Flow ID",
    "Src IP",
    "Src Port",
    "Dst IP",
    "Protocol",
    "Timestamp",
    "Label",
    "target",
    "Fwd Header Length.1",
}


def normalize_columns(dataframe: pd.DataFrame) -> pd.DataFrame:
    dataframe = dataframe.copy()
    dataframe.columns = [str(column).strip() for column in dataframe.columns]
    dataframe = dataframe.rename(columns=COLUMN_ALIASES)
    dataframe = dataframe.loc[:, ~dataframe.columns.duplicated()]
    return dataframe


def normalize_labels(series: pd.Series) -> pd.Series:
    labels = series.astype(str).str.strip().str.upper()
    return pd.Series(
        np.where(labels == "BENIGN", 0, 1),
        index=series.index,
        dtype=np.int8,
    )


def clean_features(
    dataframe: pd.DataFrame,
    feature_names: list[str] | None = None,
) -> pd.DataFrame:
    dataframe = normalize_columns(dataframe)

    dataframe = dataframe.drop(
        columns=[
            column
            for column in NON_FEATURE_COLUMNS
            if column in dataframe.columns
        ],
        errors="ignore",
    )

    for column in dataframe.columns:
        dataframe[column] = pd.to_numeric(
            dataframe[column],
            errors="coerce",
        )

    dataframe = dataframe.replace([np.inf, -np.inf], np.nan)

    if feature_names is not None:
        for column in feature_names:
            if column not in dataframe.columns:
                dataframe[column] = 0.0

        dataframe = dataframe[feature_names]

    dataframe = dataframe.fillna(0.0)

    return dataframe.astype(np.float32)


def sample_chunk_rows(
    dataframe: pd.DataFrame,
    maximum_rows: int,
    random_state: int,
) -> pd.DataFrame:
    if dataframe.empty or maximum_rows <= 0:
        return dataframe.iloc[0:0].copy()

    if len(dataframe) <= maximum_rows:
        return dataframe.copy()

    return dataframe.sample(
        n=maximum_rows,
        random_state=random_state,
    )


def sample_rows_from_file(csv_path: Path) -> pd.DataFrame:
    normal_parts: list[pd.DataFrame] = []
    attack_parts: list[pd.DataFrame] = []

    normal_count = 0
    attack_count = 0

    print()
    print(f"Lecture : {csv_path.name}")

    for chunk_number, chunk in enumerate(
        pd.read_csv(
            csv_path,
            chunksize=CHUNK_SIZE,
            low_memory=False,
            encoding="utf-8",
            encoding_errors="ignore",
        ),
        start=1,
    ):
        chunk = normalize_columns(chunk)

        if "Label" not in chunk.columns:
            continue

        chunk["target"] = normalize_labels(chunk["Label"])

        normal_chunk = chunk[chunk["target"] == 0]
        attack_chunk = chunk[chunk["target"] == 1]

        remaining_normal = MAX_NORMAL_ROWS_PER_FILE - normal_count
        remaining_attack = MAX_ATTACK_ROWS_PER_FILE - attack_count

        selected_normal = sample_chunk_rows(
            normal_chunk,
            remaining_normal,
            RANDOM_STATE + chunk_number,
        )

        selected_attack = sample_chunk_rows(
            attack_chunk,
            remaining_attack,
            RANDOM_STATE + chunk_number,
        )

        if not selected_normal.empty:
            normal_parts.append(selected_normal)
            normal_count += len(selected_normal)

        if not selected_attack.empty:
            attack_parts.append(selected_attack)
            attack_count += len(selected_attack)

        if (
            normal_count >= MAX_NORMAL_ROWS_PER_FILE
            and attack_count >= MAX_ATTACK_ROWS_PER_FILE
        ):
            break

    selected_parts = normal_parts + attack_parts

    if not selected_parts:
        raise ValueError(
            f"Aucune donnée exploitable trouvée dans {csv_path.name}"
        )

    sampled = pd.concat(selected_parts, ignore_index=True)

    print(f"Normaux sélectionnés : {normal_count}")
    print(f"Attaques sélectionnées : {attack_count}")
    print(f"Total sélectionné : {len(sampled)}")

    return sampled


def load_dataset() -> pd.DataFrame:
    csv_files = sorted(DATA_DIRECTORY.glob("*.csv"))

    if not csv_files:
        raise FileNotFoundError(
            f"Aucun fichier CSV trouvé dans : {DATA_DIRECTORY}"
        )

    datasets: list[pd.DataFrame] = []

    print(f"Nombre de fichiers trouvés : {len(csv_files)}")

    for csv_path in csv_files:
        datasets.append(sample_rows_from_file(csv_path))

    dataset = pd.concat(datasets, ignore_index=True)

    dataset = dataset.sample(
        frac=1,
        random_state=RANDOM_STATE,
    ).reset_index(drop=True)

    return dataset


def main() -> None:
    print("Démarrage de l'entraînement CICIDS2017")
    print(f"Dossier du dataset : {DATA_DIRECTORY}")

    dataset = load_dataset()

    if "target" not in dataset.columns:
        raise ValueError("La colonne target est absente.")

    y = dataset["target"].astype(np.int8)
    X = clean_features(dataset)

    feature_names = X.columns.tolist()

    print()
    print(f"Nombre total de lignes : {len(X)}")
    print(f"Nombre de caractéristiques : {len(feature_names)}")
    print(f"Nombre de flux normaux : {(y == 0).sum()}")
    print(f"Nombre de flux d'attaque : {(y == 1).sum()}")

    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=0.20,
        random_state=RANDOM_STATE,
        stratify=y,
    )

    print()
    print("Entraînement du Random Forest...")

    model = RandomForestClassifier(
        n_estimators=150,
        max_depth=25,
        min_samples_split=4,
        min_samples_leaf=2,
        class_weight="balanced",
        n_jobs=-1,
        random_state=RANDOM_STATE,
        verbose=1,
    )

    model.fit(X_train, y_train)

    print()
    print("Évaluation du modèle...")

    predictions = model.predict(X_test)

    accuracy = accuracy_score(y_test, predictions)
    precision = precision_score(
        y_test,
        predictions,
        pos_label=1,
        zero_division=0,
    )
    recall = recall_score(
        y_test,
        predictions,
        pos_label=1,
        zero_division=0,
    )
    f1 = f1_score(
        y_test,
        predictions,
        pos_label=1,
        zero_division=0,
    )

    matrix = confusion_matrix(y_test, predictions).tolist()

    report = classification_report(
        y_test,
        predictions,
        target_names=["Normal", "Attaque"],
        output_dict=True,
        zero_division=0,
    )

    print()
    print(f"Accuracy : {accuracy:.4f}")
    print(f"Precision attaque : {precision:.4f}")
    print(f"Recall attaque : {recall:.4f}")
    print(f"F1 attaque : {f1:.4f}")
    print(f"Matrice de confusion : {matrix}")

    MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)

    bundle = {
        "model": model,
        "feature_names": feature_names,
        "column_aliases": COLUMN_ALIASES,
        "non_feature_columns": sorted(NON_FEATURE_COLUMNS),
        "labels": {
            0: "Normal",
            1: "Attaque",
        },
        "dataset": "CICIDS2017",
    }

    joblib.dump(bundle, MODEL_PATH)

    REPORT_PATH.parent.mkdir(parents=True, exist_ok=True)

    metrics = {
        "dataset": "CICIDS2017",
        "rows_used": int(len(X)),
        "training_rows": int(len(X_train)),
        "testing_rows": int(len(X_test)),
        "features_used": int(len(feature_names)),
        "normal_rows": int((y == 0).sum()),
        "attack_rows": int((y == 1).sum()),
        "accuracy": float(accuracy),
        "precision_attack": float(precision),
        "recall_attack": float(recall),
        "f1_attack": float(f1),
        "confusion_matrix": matrix,
        "classification_report": report,
        "feature_names": feature_names,
    }

    with REPORT_PATH.open("w", encoding="utf-8") as file:
        json.dump(
            metrics,
            file,
            indent=4,
            ensure_ascii=False,
        )

    print()
    print("Entraînement terminé.")
    print(f"Modèle enregistré dans : {MODEL_PATH}")
    print(f"Rapport enregistré dans : {REPORT_PATH}")


if __name__ == "__main__":
    main()
