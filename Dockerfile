FROM python:3.11-slim

# Prevent .pyc files and enable unbuffered logging
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# Install OS deps needed to build tgcrypto
RUN apt-get update \
    && apt-get install -y --no-install-recommends gcc build-essential \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY bot.py .

# Required at runtime (pass via `docker run -e` or an env file):
#   API_ID, API_HASH, BOT_TOKEN, MONGO_URI, OWNER_ID
CMD ["python", "bot.py"]
