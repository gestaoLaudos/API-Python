FROM python:3.8-slim-buster

# Install gcc, g++, swig and other dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    g++ \
    libssl-dev \
    libffi-dev \
    python3-dev \
    swig \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

ADD . /app

RUN pip install --no-cache-dir -r requirements.txt

EXPOSE 80

CMD ["python", "app.py"]
