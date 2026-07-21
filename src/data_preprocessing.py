from pathlib import Path

import pandas as pd


PROJECT_ROOT = Path(__file__).resolve().parents[1]

TRAIN_DATA_PATH = (
    PROJECT_ROOT
    / "data"
    / "KDDTrain+.txt"
)

TEST_DATA_PATH = (
    PROJECT_ROOT
    / "data"
    / "KDDTest+.txt"
)

NSL_KDD_COLUMNS = [
    "duration",
    "protocol_type",
    "service",
    "flag",
    "src_bytes",
    "dst_bytes",
    "land",
    "wrong_fragment",
    "urgent",
    "hot",
    "num_failed_logins",
    "logged_in",
    "num_compromised",
    "root_shell",
    "su_attempted",
    "num_root",
    "num_file_creations",
    "num_shells",
    "num_access_files",
    "num_outbound_cmds",
    "is_host_login",
    "is_guest_login",
    "count",
    "srv_count",
    "serror_rate",
    "srv_serror_rate",
    "rerror_rate",
    "srv_rerror_rate",
    "same_srv_rate",
    "diff_srv_rate",
    "srv_diff_host_rate",
    "dst_host_count",
    "dst_host_srv_count",
    "dst_host_same_srv_rate",
    "dst_host_diff_srv_rate",
    "dst_host_same_src_port_rate",
    "dst_host_srv_diff_host_rate",
    "dst_host_serror_rate",
    "dst_host_srv_serror_rate",
    "dst_host_rerror_rate",
    "dst_host_srv_rerror_rate",
    "label",
    "difficulty",
]

CATEGORICAL_COLUMNS = [
    "protocol_type",
    "service",
    "flag",
]

TARGET_COLUMN = "binary_label"

REMOVED_COLUMNS = [
    "label",
    "difficulty",
    TARGET_COLUMN,
]


def load_nsl_kdd_file(
    file_path: str | Path,
) -> pd.DataFrame:
    file_path = Path(file_path)

    if not file_path.exists():
        raise FileNotFoundError(
            f"Fichier NSL-KDD introuvable : {file_path}"
        )

    dataframe = pd.read_csv(
        file_path,
        names=NSL_KDD_COLUMNS,
        header=None,
    )

    if dataframe.empty:
        raise ValueError(
            f"Le fichier NSL-KDD est vide : {file_path}"
        )

    return dataframe


def add_binary_target(
    dataframe: pd.DataFrame,
) -> pd.DataFrame:
    prepared_dataframe = dataframe.copy()

    prepared_dataframe[TARGET_COLUMN] = (
        prepared_dataframe["label"]
        .apply(
            lambda value: (
                0
                if value == "normal"
                else 1
            )
        )
        .astype(int)
    )

    return prepared_dataframe


def prepare_features_and_target(
    dataframe: pd.DataFrame,
) -> tuple[pd.DataFrame, pd.Series]:
    required_columns = set(
        NSL_KDD_COLUMNS
    )

    missing_columns = [
        column
        for column in required_columns
        if column not in dataframe.columns
    ]

    if missing_columns:
        raise ValueError(
            "Colonnes NSL-KDD manquantes : "
            f"{sorted(missing_columns)}"
        )

    prepared_dataframe = add_binary_target(
        dataframe
    )

    features = prepared_dataframe.drop(
        columns=REMOVED_COLUMNS
    )

    target = prepared_dataframe[
        TARGET_COLUMN
    ].copy()

    return features, target


def load_training_and_test_data() -> tuple[
    pd.DataFrame,
    pd.DataFrame,
    pd.Series,
    pd.Series,
]:
    train_dataframe = load_nsl_kdd_file(
        TRAIN_DATA_PATH
    )

    test_dataframe = load_nsl_kdd_file(
        TEST_DATA_PATH
    )

    X_train, y_train = (
        prepare_features_and_target(
            train_dataframe
        )
    )

    X_test, y_test = (
        prepare_features_and_target(
            test_dataframe
        )
    )

    return (
        X_train,
        X_test,
        y_train,
        y_test,
    )


if __name__ == "__main__":
    (
        X_train,
        X_test,
        y_train,
        y_test,
    ) = load_training_and_test_data()

    print(
        "Dimensions des données d’entraînement :",
        X_train.shape,
    )

    print(
        "Dimensions des données de test :",
        X_test.shape,
    )

    print(
        "Répartition entraînement :",
    )

    print(
        y_train.value_counts()
        .rename(
            index={
                0: "Normal",
                1: "Attaque",
            }
        )
    )

    print(
        "Répartition test :",
    )

    print(
        y_test.value_counts()
        .rename(
            index={
                0: "Normal",
                1: "Attaque",
            }
        )
    )