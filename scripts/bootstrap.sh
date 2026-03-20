#!/usr/bin/env bash
# Bootstrap TraceX on a fresh cluster
set -euo pipefail

NS=forensics-operator
ES_URL=${ELASTICSEARCH_URL:-http://localhost:9200}

echo "==> Applying Kubernetes manifests..."
make deploy

echo "==> Waiting for Elasticsearch to be ready..."
until curl -sf "${ES_URL}/_cluster/health?wait_for_status=yellow&timeout=5s" > /dev/null; do
  echo "Waiting for ES..."
  sleep 5
done
echo "Elasticsearch ready."

echo "==> Applying Elasticsearch index template..."
curl -s -X PUT "${ES_URL}/_index_template/fo-cases-template" \
  -H "Content-Type: application/json" \
  -d @elasticsearch/index_templates/fo-cases-template.json
echo ""

echo "==> Done! TraceX is running."
echo "    Frontend:  http://localhost (or your ingress hostname)"
echo "    API:       http://localhost/api/v1"
echo "    Kibana:    http://localhost/kibana"
echo "    MinIO:     http://localhost/minio"
