FROM python:3.9
WORKDIR /app
COPY watch_and_alert.py /app/watch_and_alert.py
RUN pip install kubernetes requests pyyaml google-cloud-storage
# Ensures that the output is sent straight to the terminal without being buffered
ENV PYTHONUNBUFFERED=1 
CMD ["python", "/app/watch_and_alert.py"]

