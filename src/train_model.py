from pathlib import Path
import json
import time

import joblib
from sklearn.compose import ColumnTransformer
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder

from src.data_preprocessing import (
    CATEGORICAL_COLUMNS,
    load_training_and_test_data,
)


PROJECT_ROOT = Path(__file__).resolve().parents[1]

MODELS_DIRECTORY = (
    PROJECT_ROOT
    / "models"
)

REPORTS_DIRECTORY = (
    PROJECT_ROOT
    / "reports"
)

MODEL_PATH = (
    MODELS_DIRECTORY
    / "intrusion_detector.joblib"
)

METRICS_PATH = (
    REPORTS_DIRECTORY
    / "final_metrics.json"
)

DECISION_THRESHOLD = 0.10

RANDOM_STATE = 42

NUMBER_OF_TREES = 100


def build_pipeline() -> Pipeline:
    preprocessor = ColumnTransformer(
        transformers=[
            (
                "categorical",
                OneHotEncoder(
                    handle_unknown="ignore",
                    sparse_output=True,
                ),
                CATEGORICAL_COLUMNS,
            )
        ],
        remainder="passthrough",
    )

    classifier = RandomForestClassifier(
        n_estimators=NUMBER_OF_TREES,
        random_state=RANDOM_STATE,
        n_jobs=-1,
    )

    return Pipeline(
        steps=[
            (
                "preprocessor",
                preprocessor,
            ),
            (
                "classifier",
                classifier,
            ),
        ]
    )


def calculate_metrics(
    y_true,
    predictions,
) -> dict:
    matrix = confusion_matrix(
        y_true,
        predictions,
    )

    return {
        "threshold": DECISION_THRESHOLD,
        "accuracy": float(
            accuracy_score(
                y_true,
                predictions,
            )
        ),
        "attack_precision": float(
            precision_score(
                y_true,
                predictions,
                zero_division=0,
            )
        ),
        "attack_recall": float(
            recall_score(
                y_true,
                predictions,
                zero_division=0,
            )
        ),
        "attack_f1_score": float(
            f1_score(
                y_true,
                predictions,
                zero_division=0,
            )
        ),
        "confusion_matrix": (
            matrix.tolist()
        ),
        "number_of_trees": (
            NUMBER_OF_TREES
        ),
        "random_state": RANDOM_STATE,
    }


def save_model(
    pipeline: Pipeline,
    feature_names: list[str],
) -> None:
    MODELS_DIRECTORY.mkdir(
        parents=True,
        exist_ok=True,
    )

    model_bundle = {
        "pipeline": pipeline,
        "threshold": DECISION_THRESHOLD,
        "feature_names": feature_names,
    }

    joblib.dump(
        model_bundle,
        MODEL_PATH,
    )


def save_metrics(
    metrics: dict,
) -> None:
    REPORTS_DIRECTORY.mkdir(
        parents=True,
        exist_ok=True,
    )

    with open(
        METRICS_PATH,
        "w",
        encoding="utf-8",
    ) as file:
        json.dump(
            metrics,
            file,
            indent=4,
            ensure_ascii=False,
        )


def train_model() -> None:
    print(
        "Chargement des données NSL-KDD..."
    )

    (
        X_train,
        X_test,
        y_train,
        y_test,
    ) = load_training_and_test_data()

    print(
        "Données d’entraînement :",
        X_train.shape,
    )

    print(
        "Données de test :",
        X_test.shape,
    )

    pipeline = build_pipeline()

    print(
        "Entraînement du modèle..."
    )

    start_time = time.perf_counter()

    pipeline.fit(
        X_train,
        y_train,
    )

    training_duration = (
        time.perf_counter()
        - start_time
    )

    print(
        "Entraînement terminé en",
        round(training_duration, 2),
        "secondes.",
    )

    print(
        "Calcul des probabilités..."
    )

    attack_probabilities = (
        pipeline.predict_proba(
            X_test
        )[:, 1]
    )

    predictions = (
        attack_probabilities
        >= DECISION_THRESHOLD
    ).astype(int)

    metrics = calculate_metrics(
        y_test,
        predictions,
    )

    metrics["training_duration_seconds"] = (
        round(
            training_duration,
            4,
        )
    )

    print()
    print(
        classification_report(
            y_test,
            predictions,
            target_names=[
                "Normal",
                "Attaque",
            ],
            zero_division=0,
        )
    )

    print(
        "Accuracy :",
        round(
            metrics["accuracy"],
            4,
        ),
    )

    print(
        "Précision attaque :",
        round(
            metrics[
                "attack_precision"
            ],
            4,
        ),
    )

    print(
        "Rappel attaque :",
        round(
            metrics[
                "attack_recall"
            ],
            4,
        ),
    )

    print(
        "F1-score attaque :",
        round(
            metrics[
                "attack_f1_score"
            ],
            4,
        ),
    )

    print(
        "Matrice de confusion :",
        metrics["confusion_matrix"],
    )

    save_model(
        pipeline=pipeline,
        feature_names=list(
            X_train.columns
        ),
    )

    save_metrics(
        metrics
    )

    print()
    print(
        "Modèle sauvegardé dans :",
        MODEL_PATH,
    )

    print(
        "Métriques sauvegardées dans :",
        METRICS_PATH,
    )


if __name__ == "__main__":
    try:
        train_model()

    except (
        FileNotFoundError,
        ValueError,
        KeyError,
    ) as error:
        print(
            f"Erreur : {error}"
        )