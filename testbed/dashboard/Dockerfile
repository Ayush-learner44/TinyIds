# TinyIDS dashboard for the Docker testbed. Uses the SAME file as the laptop (deploy/laptop/dashboard.py).
# Build context = the repository root (see docker-compose.yml).
FROM python:3.12-slim
RUN pip install --no-cache-dir streamlit==1.39.0 paho-mqtt==2.1.0 pandas
COPY deploy/laptop/dashboard.py /app/dashboard.py
WORKDIR /app
EXPOSE 8501
CMD ["streamlit", "run", "dashboard.py", "--server.port=8501", "--server.address=0.0.0.0", \
     "--server.headless=true", "--browser.gatherUsageStats=false"]
