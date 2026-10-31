"""
Task management and monitoring endpoints.
"""

from typing import Any, Dict, Optional

import logging

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from ..celery_app import celery_app
from ..dependencies.auth import require_role
from ..models import UserRole
from ..tasks import get_llm_stats, process_llm_queue, process_new_cves

logger = logging.getLogger(__name__)

router = APIRouter()


class TaskResponse(BaseModel):
    task_id: str
    status: str
    message: str


class TaskStatusResponse(BaseModel):
    task_id: str
    status: str
    result: Optional[Dict[str, Any]] = None
    error: Optional[str] = None


@router.post(
    "/tasks/process-new-cves",
    response_model=TaskResponse,
    dependencies=[Depends(require_role(UserRole.ANALYST))],
)
async def trigger_new_cves_processing():
    """
    Manually trigger processing of new CVEs.

    **Requires:** ANALYST role or higher

    Processes CVEs added in the last hour with LLM.
    """
    task = process_new_cves.delay()

    return TaskResponse(
        task_id=task.id, status="pending", message="New CVEs processing task started."
    )


@router.post(
    "/tasks/process-llm-batch",
    response_model=TaskResponse,
    dependencies=[Depends(require_role(UserRole.ANALYST))],
)
async def trigger_llm_batch(batch_size: int = 10, priority: str = "high"):
    """
    Manually trigger batch LLM processing.

    **Requires:** ANALYST role or higher

    Args:
        batch_size: Number of CVEs to process (1-100)
        priority: Priority level (high, medium, low)
    """
    if priority not in ["high", "medium", "low"]:
        raise HTTPException(status_code=400, detail="Invalid priority")

    if batch_size < 1 or batch_size > 100:
        raise HTTPException(status_code=400, detail="Batch size must be 1-100")

    task = process_llm_queue.delay(batch_size=batch_size, priority=priority)

    return TaskResponse(
        task_id=task.id,
        status="pending",
        message=f"LLM batch processing started: {batch_size} CVEs with {priority} priority",
    )


@router.get("/tasks/llm-stats", dependencies=[Depends(require_role(UserRole.ANALYST))])
def get_llm_processing_stats():
    """
    Get LLM processing statistics.

    Shows progress of CVE processing with LLM.
    """
    try:
        # Called directly (not queued): three COUNT queries are cheap, and queueing
        # them behind the single Celery worker made this request wait for it.
        return get_llm_stats()
    except Exception:
        logger.exception("LLM stats failed")
        raise HTTPException(status_code=500, detail="Could not read the LLM statistics")


@router.get(
    "/tasks/{task_id}", response_model=TaskStatusResponse, dependencies=[Depends(require_role(UserRole.ANALYST))]
)
async def get_task_status(task_id: str):
    """
    Get the status of a background task.

    **Status values:**
    - `PENDING`: Task is waiting to be executed
    - `STARTED`: Task has started
    - `SUCCESS`: Task completed successfully
    - `FAILURE`: Task failed
    - `RETRY`: Task is being retried
    """
    task_result = celery_app.AsyncResult(task_id)

    response = TaskStatusResponse(
        task_id=task_id,
        status=task_result.status,
    )

    if task_result.successful():
        response.result = task_result.result
    elif task_result.failed():
        response.error = str(task_result.info)

    return response


@router.get("/tasks/scheduled/list", dependencies=[Depends(require_role(UserRole.ANALYST))])
async def list_scheduled_tasks():
    """
    List all scheduled tasks (Beat schedule).

    Shows which tasks run automatically and their schedules.
    """
    schedule = celery_app.conf.beat_schedule

    tasks = []
    for name, config in schedule.items():
        tasks.append(
            {
                "name": name,
                "task": config["task"],
                "schedule": str(config["schedule"]),
                "description": _get_task_description(config["task"]),
            }
        )

    return {"scheduled_tasks": tasks, "total": len(tasks)}


@router.get("/tasks/workers/status", dependencies=[Depends(require_role(UserRole.ANALYST))])
def get_workers_status():
    """
    Get status of Celery workers.

    Shows which workers are active and their statistics.
    """
    try:
        # Inspect active workers
        # Each inspect call waits for the workers' reply up to ``timeout`` seconds,
        # so the three calls below take at most about 3 s. This is a plain ``def``
        # handler (worker thread): waiting here must not block the event loop.
        inspect = celery_app.control.inspect(timeout=1.0)

        active_workers = inspect.active()
        registered_tasks = inspect.registered()
        stats = inspect.stats()

        if not active_workers:
            return {
                "status": "no_workers",
                "message": "No Celery workers are running",
                "workers": [],
            }

        workers = []
        for worker_name in active_workers.keys():
            worker_info = {
                "name": worker_name,
                "active_tasks": len(active_workers.get(worker_name, [])),
                "registered_tasks": len(registered_tasks.get(worker_name, [])),
                "stats": stats.get(worker_name, {}),
            }
            workers.append(worker_info)

        return {"status": "healthy", "workers": workers, "total_workers": len(workers)}

    except Exception:
        logger.exception("Celery worker inspection failed")
        raise HTTPException(status_code=503, detail="Could not reach the Celery workers")


def _get_task_description(task_name: str) -> str:
    """Get human-readable description for a task."""
    descriptions = {
        "tasks.process_new_cves": "Process newly added CVEs with LLM",
        "tasks.process_llm_queue": "Process CVE queue with LLM (priority-based)",
        "tasks.process_cve_with_llm": "Process single CVE with LLM",
    }
    return descriptions.get(task_name, "No description available")
