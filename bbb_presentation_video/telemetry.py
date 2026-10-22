# SPDX-FileCopyrightText: 2026 BigBlueButton Inc. and by respective authors
#
# SPDX-License-Identifier: GPL-3.0-or-later

"""Optional OTLP tracing, only when OTEL_EXPORTER_OTLP_ENDPOINT is set and the
OpenTelemetry packages are installed. The standard OTEL_* variables configure it."""

import os
from contextlib import contextmanager
from typing import Any, Iterator, Optional

SERVICE_NAME = "bbb-presentation-video"


def _start() -> Optional[Any]:
    if (
        not os.environ.get("OTEL_EXPORTER_OTLP_ENDPOINT")
        or os.environ.get("OTEL_SDK_DISABLED") == "true"
    ):
        return None
    try:
        from opentelemetry.exporter.otlp.proto.http.trace_exporter import (
            OTLPSpanExporter,
        )
        from opentelemetry.sdk.resources import Resource
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import BatchSpanProcessor
    except ImportError:
        return None

    # OTEL_SERVICE_NAME overrides the default
    attributes = (
        {} if os.environ.get("OTEL_SERVICE_NAME") else {"service.name": SERVICE_NAME}
    )
    provider = TracerProvider(resource=Resource.create(attributes))
    provider.add_span_processor(BatchSpanProcessor(OTLPSpanExporter()))
    return provider


@contextmanager
def render_span(meeting_id: str) -> Iterator[None]:
    """Span around the render, continuing the trace of the TRACEPARENT variable."""
    provider = _start()
    if provider is None:
        yield
        return

    from opentelemetry.trace.propagation.tracecontext import (
        TraceContextTextMapPropagator,
    )

    traceparent = os.environ.get("TRACEPARENT")
    parent = (
        TraceContextTextMapPropagator().extract({"traceparent": traceparent})
        if traceparent
        else None
    )
    try:
        with provider.get_tracer(SERVICE_NAME).start_as_current_span(
            "render", context=parent, attributes={"bbb.meeting.id": meeting_id}
        ):
            yield
    finally:
        provider.shutdown()
