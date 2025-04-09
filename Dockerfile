FROM python:3.9
WORKDIR /app
COPY watch_and_alert.py /app/watch_and_alert.py
RUN pip install kubernetes requests
CMD ["python", "/app/watch_and_alert.py"]

