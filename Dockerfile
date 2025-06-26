FROM python:3.11
WORKDIR /app
COPY watch_and_report.py /app/watch_and_report.py
COPY generate_report.py /app/generate_report.py
RUN pip install kubernetes requests pyyaml google-cloud-storage
# Ensures that the output is sent straight to the terminal without being buffered
ENV PYTHONUNBUFFERED=1 
CMD ["python", "/app/watch_and_report.py"]

