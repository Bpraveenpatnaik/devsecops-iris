FROM python:3.11-slim

WORKDIR /app
ENV PYTHONUNBUFFERED=1

# Install requirements
COPY requirements.txt requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

COPY main.py ml_utils.py ./

# run as a non-root user
RUN useradd --create-home appuser
USER appuser

EXPOSE 8888
CMD ["python", "main.py"]
