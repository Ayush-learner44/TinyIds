FROM python:3.12-slim
RUN pip install --no-cache-dir streamlit==1.39.0 paho-mqtt==2.1.0 pandas
COPY app.py /app/app.py
WORKDIR /app
EXPOSE 8501
CMD ["streamlit", "run", "app.py", "--server.port=8501", "--server.address=0.0.0.0", \
     "--server.headless=true", "--browser.gatherUsageStats=false"]
