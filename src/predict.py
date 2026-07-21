
from pathlib import Path

import joblib
import pandas as pd


PROJECT_ROOT = Path(__file__).resolve().parents[1]
MODEL_PATH = PROJECT_ROOT / "models" / "intrusion_detector.joblib"
SAMPLE_PATH = PROJECT_ROOT / "data" / "sample_connection.csv"


def load_detector():
    if not MODEL_PATH.exists():
        raise FileNotFoundError(
            f"Modèle introuvable : {MODEL_PATH}"
        )

    return joblib.load(MODEL_PATH)


def predict_connections(data: pd.DataFrame) -> pd.DataFrame:
    bundle = load_detector()

    pipeline = bundle["pipeline"]
    threshold = bundle["threshold"]
    feature_names = bundle["feature_names"]

    missing_columns = [
        column
        for column in feature_names
        if column not in data.columns
    ]

    if missing_columns:
        raise ValueError(
            f"Colonnes manquantes : {missing_columns}"
        )

    data = data[feature_names]

    attack_probabilities = pipeline.predict_proba(data)[:, 1]

    predictions = (
        attack_probabilities >= threshold
    ).astype(int)

    result = data.copy()
    result["attack_probability"] = attack_probabilities
    result["prediction"] = [
        "Attaque" if prediction == 1 else "Normal"
        for prediction in predictions
    ]

    return result


if __name__ == "__main__":
    if not SAMPLE_PATH.exists():
        raise FileNotFoundError(
            f"Fichier exemple introuvable : {SAMPLE_PATH}"
        )

    sample = pd.read_csv(SAMPLE_PATH)
    result = predict_connections(sample)

    print(
        result[
            ["attack_probability", "prediction"]
        ].to_string(index=False)
    )
