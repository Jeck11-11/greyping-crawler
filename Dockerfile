FROM python:3.11-alpine

WORKDIR /app

RUN apk add --no-cache docker-cli curl

COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

COPY api.py worker.py /app/

ENV PYTHONUNBUFFERED=1

CMD ["python", "-m", "api"]
