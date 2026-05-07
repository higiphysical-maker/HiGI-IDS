FROM python:3.11-slim

WORKDIR /app

# Instalar dependencias del sistema (opcional, pero útil para depuración)
RUN apt-get update && apt-get install -y --no-install-recommends \
    tini \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Crear directorios de salida con permisos de escritura para el usuario no root
RUN mkdir -p /app/data/processed /app/models /app/reports \
    && chmod -R 777 /app/data /app/models /app/reports

# Usar tini para una correcta gestión de señales
ENTRYPOINT ["tini", "--", "python", "main.py"]