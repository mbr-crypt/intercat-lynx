#!/bin/bash
# Check Celery worker and beat status

echo "Celery Status Check"
echo "======================"
echo ""

# Check if containers are running
echo "1. Container Status:"
docker compose -f docker-compose.prod.yml ps celery-worker celery-beat | grep -E "NAME|celery"
echo ""

# Check Celery worker status
echo "2. Celery Workers:"
WORKERS=$(docker compose -f docker-compose.prod.yml exec -T celery-worker celery -A backend.celery_app inspect active 2>/dev/null | grep -c "celery@")
echo "   Active workers: $WORKERS"
echo ""

# Check Celery beat (scheduler)
echo "3. Celery Beat (Scheduler):"
BEAT_RUNNING=$(docker compose -f docker-compose.prod.yml ps celery-beat | grep -c "Up")
if [ "$BEAT_RUNNING" -gt 0 ]; then
    echo "   Celery Beat is running"
else
    echo "   Celery Beat is NOT running"
fi
echo ""

# Check scheduled tasks
echo "4. Scheduled Tasks (Beat Schedule):"
docker compose -f docker-compose.prod.yml logs --tail=50 celery-beat 2>/dev/null | grep -E "Scheduler:|beat:" | tail -5
echo ""

# Check recent task executions
echo "5. Recent Task Executions (last 10):"
docker compose -f docker-compose.prod.yml logs --tail=100 celery-worker 2>/dev/null | grep -E "Task.*received|Task.*succeeded" | tail -10
echo ""

# Check for errors
echo "6. Recent Errors (if any):"
ERRORS=$(docker compose -f docker-compose.prod.yml logs --tail=100 celery-worker 2>/dev/null | grep -i "error" | tail -5)
if [ -z "$ERRORS" ]; then
    echo "   No recent errors"
else
    echo "$ERRORS"
fi
echo ""

# Check Redis connection
echo "7. Redis Connection:"
REDIS_STATUS=$(docker compose -f docker-compose.prod.yml exec -T redis redis-cli ping 2>/dev/null)
if [ "$REDIS_STATUS" = "PONG" ]; then
    echo "   Redis is responding"
else
    echo "   Redis is NOT responding"
fi
echo ""

# Check database stats
echo "8. Processing Stats:"
docker compose -f docker-compose.prod.yml exec -T postgres psql -U openthreat -d openthreat -t -c "
SELECT 
  'Total: ' || COUNT(*) || 
  ' | Processed: ' || COUNT(*) FILTER (WHERE llm_processed = true) || 
  ' (' || ROUND(COUNT(*) FILTER (WHERE llm_processed = true)::numeric / COUNT(*)::numeric * 100, 1) || '%)' ||
  ' | Unprocessed: ' || COUNT(*) FILTER (WHERE llm_processed = false)
FROM vulnerabilities;
" 2>/dev/null | xargs echo "   "
echo ""

# Check last processed CVE
echo "9. Last Processed CVE:"
docker compose -f docker-compose.prod.yml exec -T postgres psql -U openthreat -d openthreat -t -c "
SELECT '   ' || cve_id || ' - ' || TO_CHAR(llm_processed_at, 'YYYY-MM-DD HH24:MI:SS')
FROM vulnerabilities 
WHERE llm_processed = true 
ORDER BY llm_processed_at DESC 
LIMIT 1;
" 2>/dev/null
echo ""

echo "Status check complete!"
echo ""
echo "Useful commands:"
echo "   Watch live: docker compose -f docker-compose.prod.yml logs -f celery-worker"
echo "   Restart workers: docker compose -f docker-compose.prod.yml restart celery-worker celery-beat"
echo "   Check active tasks: docker compose -f docker-compose.prod.yml exec celery-worker celery -A backend.celery_app inspect active"
