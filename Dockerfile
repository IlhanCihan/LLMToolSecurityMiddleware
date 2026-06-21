FROM python:3.11-slim

WORKDIR /app

COPY pyproject.toml README.md ./
COPY middleware ./middleware
COPY policies ./policies
COPY examples ./examples

RUN pip install --no-cache-dir -e .

CMD ["python", "-m", "middleware.demo"]
