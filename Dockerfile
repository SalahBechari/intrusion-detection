FROM eclipse-temurin:8-jdk-jammy AS java8

FROM python:3.12-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV DEBIAN_FRONTEND=noninteractive

ENV APP_HOME=/app
ENV JAVA_HOME=/opt/java/openjdk
ENV PATH="${JAVA_HOME}/bin:${PATH}"

ENV CICFLOWMETER_DIRECTORY=/opt/CICFlowMeter
ENV TSHARK_PATH=/usr/bin/tshark
ENV CICIDS_MODEL_PATH=/app/models/cicids_intrusion_detector.joblib
ENV JNETPCAP_DIRECTORY=/opt/CICFlowMeter/jnetpcap/linux/jnetpcap-1.4.r1425
ENV LD_LIBRARY_PATH=/opt/CICFlowMeter/jnetpcap/linux/jnetpcap-1.4.r1425

COPY --from=java8 /opt/java/openjdk /opt/java/openjdk

WORKDIR ${APP_HOME}

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        git \
        tshark \
        libpcap-dev \
        maven \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN java -version

RUN git clone \
    https://github.com/ahlashkari/CICFlowMeter.git \
    ${CICFLOWMETER_DIRECTORY}

WORKDIR ${CICFLOWMETER_DIRECTORY}/jnetpcap/linux/jnetpcap-1.4.r1425

RUN mvn install:install-file \
    -Dfile=jnetpcap.jar \
    -DgroupId=org.jnetpcap \
    -DartifactId=jnetpcap \
    -Dversion=1.4.1 \
    -Dpackaging=jar

WORKDIR ${CICFLOWMETER_DIRECTORY}

RUN chmod +x gradlew \
    && ./gradlew classes --no-daemon

WORKDIR ${APP_HOME}

COPY requirements.txt .

RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 8000

CMD ["python", "-m", "uvicorn", "src.api:app", "--host", "0.0.0.0", "--port", "8000"]
