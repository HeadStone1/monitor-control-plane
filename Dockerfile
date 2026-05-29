FROM python:3.11-slim AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

RUN useradd --system --uid 10001 --create-home --shell /usr/sbin/nologin monitor

COPY requirements.txt /app/requirements.txt
RUN python -m pip install --no-cache-dir --upgrade pip \
    && python -m pip install --no-cache-dir -r /app/requirements.txt

COPY agent /app/agent
COPY server /app/server
COPY web /app/web

RUN mkdir -p /app/data \
    && chown -R monitor:monitor /app/data

FROM base AS server
USER monitor
EXPOSE 8000
CMD ["python", "-m", "server.monitor_server", "--config", "/config/server.yaml"]

FROM base AS agent
USER monitor
CMD ["python", "-m", "agent.monitor_agent", "--config", "/config/agent.yaml"]
