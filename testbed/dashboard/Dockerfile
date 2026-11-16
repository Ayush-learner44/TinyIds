# Dashboard for the retrain testbed: a copy of laptop/dashboard.py (only the model caption changed).
FROM python:3.12-slim
RUN pip install --no-cache-dir streamlit==1.39.0 paho-mqtt==2.1.0 pandas
COPY dashboard.py /app/dashboard.py
WORKDIR /app
EXPOSE 8501
CMD ["streamlit", "run", "dashboard.py", "--server.port=8501", "--server.address=0.0.0.0", \
     "--server.headless=true", "--browser.gatherUsageStats=false"]
