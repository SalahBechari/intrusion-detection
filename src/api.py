from io import BytesIO
from pathlib import Path
import json
import tempfile

import joblib
import pandas as pd
from fastapi import (
    FastAPI,
    File,
    HTTPException,
    Request,
    UploadFile,
)
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, ConfigDict

from src.pcap_analyzer import analyze_pcap
from src.pcap_ml_analyzer import analyze_pcap_with_ml


PROJECT_ROOT = Path(__file__).resolve().parents[1]

MODEL_PATH = (
    PROJECT_ROOT
    / "models"
    / "intrusion_detector.joblib"
)

EXAMPLES_PATH = (
    PROJECT_ROOT
    / "data"
    / "examples.json"
)

STATIC_DIRECTORY = PROJECT_ROOT / "static"
TEMPLATES_DIRECTORY = PROJECT_ROOT / "templates"


if not MODEL_PATH.exists():
    raise FileNotFoundError(
        f"Modèle introuvable : {MODEL_PATH}"
    )


model_bundle = joblib.load(MODEL_PATH)

pipeline = model_bundle["pipeline"]
threshold = float(model_bundle["threshold"])
feature_names = model_bundle["feature_names"]


app = FastAPI(
    title="Intrusion Detection API",
    description=(
        "API de détection d'intrusions réseau "
        "et d'analyse de captures Wireshark."
    ),
    version="1.0.0",
)


app.mount(
    "/static",
    StaticFiles(directory=STATIC_DIRECTORY),
    name="static",
)


templates = Jinja2Templates(
    directory=TEMPLATES_DIRECTORY
)


class ConnectionInput(BaseModel):
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "duration": 0,
                "protocol_type": "tcp",
                "service": "http",
                "flag": "SF",
                "src_bytes": 181,
                "dst_bytes": 5450,
                "land": 0,
                "wrong_fragment": 0,
                "urgent": 0,
                "hot": 0,
                "num_failed_logins": 0,
                "logged_in": 1,
                "num_compromised": 0,
                "root_shell": 0,
                "su_attempted": 0,
                "num_root": 0,
                "num_file_creations": 0,
                "num_shells": 0,
                "num_access_files": 0,
                "num_outbound_cmds": 0,
                "is_host_login": 0,
                "is_guest_login": 0,
                "count": 8,
                "srv_count": 8,
                "serror_rate": 0.0,
                "srv_serror_rate": 0.0,
                "rerror_rate": 0.0,
                "srv_rerror_rate": 0.0,
                "same_srv_rate": 1.0,
                "diff_srv_rate": 0.0,
                "srv_diff_host_rate": 0.0,
                "dst_host_count": 9,
                "dst_host_srv_count": 9,
                "dst_host_same_srv_rate": 1.0,
                "dst_host_diff_srv_rate": 0.0,
                "dst_host_same_src_port_rate": 0.11,
                "dst_host_srv_diff_host_rate": 0.0,
                "dst_host_serror_rate": 0.0,
                "dst_host_srv_serror_rate": 0.0,
                "dst_host_rerror_rate": 0.0,
                "dst_host_srv_rerror_rate": 0.0,
            }
        }
    )

    duration: int
    protocol_type: str
    service: str
    flag: str
    src_bytes: int
    dst_bytes: int
    land: int
    wrong_fragment: int
    urgent: int
    hot: int
    num_failed_logins: int
    logged_in: int
    num_compromised: int
    root_shell: int
    su_attempted: int
    num_root: int
    num_file_creations: int
    num_shells: int
    num_access_files: int
    num_outbound_cmds: int
    is_host_login: int
    is_guest_login: int
    count: int
    srv_count: int
    serror_rate: float
    srv_serror_rate: float
    rerror_rate: float
    srv_rerror_rate: float
    same_srv_rate: float
    diff_srv_rate: float
    srv_diff_host_rate: float
    dst_host_count: int
    dst_host_srv_count: int
    dst_host_same_srv_rate: float
    dst_host_diff_srv_rate: float
    dst_host_same_src_port_rate: float
    dst_host_srv_diff_host_rate: float
    dst_host_serror_rate: float
    dst_host_srv_serror_rate: float
    dst_host_rerror_rate: float
    dst_host_srv_rerror_rate: float


class PredictionOutput(BaseModel):
    prediction: str
    attack_probability: float
    threshold: float


class BatchPredictionItem(BaseModel):
    row_number: int
    prediction: str
    attack_probability: float


class BatchPredictionOutput(BaseModel):
    total_connections: int
    normal_connections: int
    attack_connections: int
    threshold: float
    predictions: list[BatchPredictionItem]


@app.get(
    "/",
    response_class=HTMLResponse,
)
def home(request: Request):
    return templates.TemplateResponse(
        request=request,
        name="index.html",
        context={
            "threshold": threshold,
        },
    )


@app.get("/health")
def health():
    return {
        "status": "ok",
        "model_loaded": True,
        "threshold": threshold,
        "number_of_features": len(feature_names),
    }


@app.get("/examples/{example_type}")
def get_example(example_type: str):
    if example_type not in {
        "normal",
        "attack",
    }:
        raise HTTPException(
            status_code=400,
            detail=(
                "Le type doit être "
                "'normal' ou 'attack'."
            ),
        )

    if not EXAMPLES_PATH.exists():
        raise HTTPException(
            status_code=404,
            detail=(
                "Le fichier des exemples "
                "est introuvable."
            ),
        )

    try:
        with open(
            EXAMPLES_PATH,
            "r",
            encoding="utf-8",
        ) as file:
            examples = json.load(file)

        return examples[example_type]

    except (
        OSError,
        json.JSONDecodeError,
        KeyError,
    ) as error:
        raise HTTPException(
            status_code=500,
            detail=(
                "Impossible de charger "
                f"l'exemple : {error}"
            ),
        ) from error


@app.post(
    "/predict",
    response_model=PredictionOutput,
)
def predict_connection(
    connection: ConnectionInput,
) -> PredictionOutput:
    connection_data = connection.model_dump()

    dataframe = pd.DataFrame(
        [connection_data],
        columns=feature_names,
    )

    try:
        attack_probability = float(
            pipeline.predict_proba(
                dataframe
            )[0, 1]
        )

    except Exception as error:
        raise HTTPException(
            status_code=500,
            detail=(
                "Erreur pendant la prédiction : "
                f"{error}"
            ),
        ) from error

    prediction = (
        "Attaque"
        if attack_probability >= threshold
        else "Normal"
    )

    return PredictionOutput(
        prediction=prediction,
        attack_probability=round(
            attack_probability,
            4,
        ),
        threshold=threshold,
    )


@app.post(
    "/predict-csv",
    response_model=BatchPredictionOutput,
)
async def predict_csv(
    file: UploadFile = File(...),
) -> BatchPredictionOutput:
    if not file.filename:
        raise HTTPException(
            status_code=400,
            detail="Nom du fichier manquant.",
        )

    if not file.filename.lower().endswith(
        ".csv"
    ):
        raise HTTPException(
            status_code=400,
            detail=(
                "Le fichier doit être "
                "au format CSV."
            ),
        )

    try:
        content = await file.read()

        dataframe = pd.read_csv(
            BytesIO(content)
        )

    except Exception as error:
        raise HTTPException(
            status_code=400,
            detail=(
                "Impossible de lire le fichier "
                f"CSV : {error}"
            ),
        ) from error

    if dataframe.empty:
        raise HTTPException(
            status_code=400,
            detail="Le fichier CSV est vide.",
        )

    missing_columns = [
        column
        for column in feature_names
        if column not in dataframe.columns
    ]

    if missing_columns:
        raise HTTPException(
            status_code=422,
            detail={
                "message": (
                    "Certaines colonnes "
                    "sont manquantes."
                ),
                "missing_columns": missing_columns,
            },
        )

    model_data = dataframe[
        feature_names
    ].copy()

    try:
        probabilities = pipeline.predict_proba(
            model_data
        )[:, 1]

    except Exception as error:
        raise HTTPException(
            status_code=500,
            detail=(
                "Erreur pendant la prédiction : "
                f"{error}"
            ),
        ) from error

    predicted_classes = (
        probabilities >= threshold
    ).astype(int)

    predictions = []

    for row_number, (
        probability,
        predicted_class,
    ) in enumerate(
        zip(
            probabilities,
            predicted_classes,
        ),
        start=1,
    ):
        predictions.append(
            BatchPredictionItem(
                row_number=row_number,
                prediction=(
                    "Attaque"
                    if predicted_class == 1
                    else "Normal"
                ),
                attack_probability=round(
                    float(probability),
                    4,
                ),
            )
        )

    attack_count = int(
        predicted_classes.sum()
    )

    normal_count = int(
        len(predicted_classes)
        - attack_count
    )

    return BatchPredictionOutput(
        total_connections=len(
            predicted_classes
        ),
        normal_connections=normal_count,
        attack_connections=attack_count,
        threshold=threshold,
        predictions=predictions,
    )


@app.post("/analyze-pcap")
async def analyze_pcap_file(
    file: UploadFile = File(...),
):
    if not file.filename:
        raise HTTPException(
            status_code=400,
            detail="Nom du fichier manquant.",
        )

    original_filename = Path(
        file.filename
    ).name

    extension = Path(
        original_filename
    ).suffix.lower()

    if extension not in {
        ".pcap",
        ".pcapng",
    }:
        raise HTTPException(
            status_code=400,
            detail=(
                "Le fichier doit être au format "
                ".pcap ou .pcapng."
            ),
        )

    temporary_path = None

    try:
        content = await file.read()

        if not content:
            raise HTTPException(
                status_code=400,
                detail=(
                    "Le fichier de capture "
                    "est vide."
                ),
            )

        with tempfile.NamedTemporaryFile(
            delete=False,
            suffix=extension,
        ) as temporary_file:
            temporary_file.write(content)

            temporary_path = Path(
                temporary_file.name
            )

        analysis = analyze_pcap(
            temporary_path
        )

        machine_learning_analysis = (
            analyze_pcap_with_ml(
                temporary_path
            )
        )

        analysis["filename"] = original_filename
        analysis["machine_learning"] = (
            machine_learning_analysis
        )

        return analysis

    except HTTPException:
        raise

    except (
        FileNotFoundError,
        ValueError,
        RuntimeError,
    ) as error:
        raise HTTPException(
            status_code=500,
            detail=str(error),
        ) from error

    finally:
        if (
            temporary_path is not None
            and temporary_path.exists()
        ):
            try:
                temporary_path.unlink()
            except OSError:
                pass