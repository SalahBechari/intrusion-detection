from pathlib import Path
import json

import joblib
import numpy as np
import pandas as pd


PROJECT_ROOT = Path(__file__).resolve().parent.parent

MODEL_PATH = PROJECT_ROOT / "models" / "cicids_intrusion_detector.joblib"

INPUT_CSV = (
    PROJECT_ROOT
    / "data"
    / "flows"
    / "test_capture.pcap_Flow.csv"
)

OUTPUT_CSV = (
    PROJECT_ROOT
    / "reports"
    / "test_capture_predictions.csv"
)

OUTPUT_JSON = (
    PROJECT_ROOT
    / "reports"
    / "test_capture_summary.json"
)


def normalize_columns(
    dataframe: pd.DataFrame,
    column_aliases: dict,
) -> pd.DataFrame:
    dataframe = dataframe.copy()

    dataframe.columns = [
        str(column).strip()
        for column in dataframe.columns
    ]

    dataframe = dataframe.rename(columns=column_aliases)

    dataframe = dataframe.loc[
        :,
        ~dataframe.columns.duplicated()
    ]

    return dataframe


def prepare_features(
    dataframe: pd.DataFrame,
    feature_names: list[str],
    column_aliases: dict,
    non_feature_columns: list[str],
) -> pd.DataFrame:
    dataframe = normalize_columns(
        dataframe,
        column_aliases,
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

    dataframe = dataframe[feature_names]

    dataframe = dataframe.fillna(0.0)

    return dataframe.astype(np.float32)


def main() -> None:
    if not MODEL_PATH.exists():
        raise FileNotFoundError(
            f"Modèle introuvable : {MODEL_PATH}"
        )

    if not INPUT_CSV.exists():
        raise FileNotFoundError(
            f"CSV introuvable : {INPUT_CSV}"
        )

    print(f"Chargement du modèle : {MODEL_PATH}")

    bundle = joblib.load(MODEL_PATH)

    model = bundle["model"]
    feature_names = bundle["feature_names"]
    column_aliases = bundle["column_aliases"]
    non_feature_columns = bundle["non_feature_columns"]
    labels = bundle["labels"]

    print(f"Lecture du CSV : {INPUT_CSV}")

    raw_dataframe = pd.read_csv(
        INPUT_CSV,
        low_memory=False,
    )

    features = prepare_features(
        raw_dataframe,
        feature_names,
        column_aliases,
        non_feature_columns,
    )

    predictions = model.predict(features)

    if hasattr(model, "predict_proba"):
        probabilities = model.predict_proba(features)[:, 1]
    else:
        probabilities = predictions.astype(float)

    result = raw_dataframe.copy()

    result["Prediction"] = [
        labels[int(value)]
        for value in predictions
    ]

    result["Attack Probability"] = probabilities

    total_flows = len(result)
    normal_flows = int((predictions == 0).sum())
    attack_flows = int((predictions == 1).sum())

    attack_percentage = (
        attack_flows / total_flows * 100
        if total_flows > 0
        else 0.0
    )

    global_result = (
        "Attaque détectée"
        if attack_flows > 0
        else "Trafic normal"
    )

    OUTPUT_CSV.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    result.to_csv(
        OUTPUT_CSV,
        index=False,
    )

    summary = {
        "input_file": str(INPUT_CSV),
        "total_flows": total_flows,
        "normal_flows": normal_flows,
        "attack_flows": attack_flows,
        "attack_percentage": attack_percentage,
        "global_result": global_result,
        "model": "CICIDS2017 Random Forest",
    }

    with OUTPUT_JSON.open(
        "w",
        encoding="utf-8",
    ) as file:
        json.dump(
            summary,
            file,
            indent=4,
            ensure_ascii=False,
        )

    print()
    print("Analyse terminée.")
    print(f"Nombre total de flux : {total_flows}")
    print(f"Flux normaux : {normal_flows}")
    print(f"Flux suspects : {attack_flows}")
    print(
        f"Pourcentage suspect : "
        f"{attack_percentage:.2f} %"
    )
    print(f"Résultat global : {global_result}")
    print()
    print(f"Prédictions : {OUTPUT_CSV}")
    print(f"Résumé : {OUTPUT_JSON}")


if __name__ == "__main__":
    main()
