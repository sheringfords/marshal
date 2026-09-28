//! Stress: 10k execute_once no leak, ensures cache bounded.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use marshall::{Tool, ToolOutcome, ToolRegistry};
use serde_json::{json, Value};

struct Counter {
    calls: AtomicUsize,
}

#[async_trait::async_trait]
impl Tool for Counter {
    fn name(&self) -> &str {
        "counter"
    }
    fn description(&self) -> &str {
        "counter"
    }
    fn parameters_schema(&self) -> Value {
        json!({})
    }
    async fn execute(&self, _args: Value) -> anyhow::Result<ToolOutcome> {
        let n = self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(ToolOutcome::success("counter", json!({"n": n}), 0))
    }
}

#[tokio::test]
async fn ten_k_execute_once_bounded() {
    let tool = Arc::new(Counter {
        calls: AtomicUsize::new(0),
    });
    let mut reg = ToolRegistry::new()
        .with_cache_capacity(1024)
        .with_cache_ttl(std::time::Duration::from_secs(300));
    reg.register(tool.clone());

    // 10k distinct keys, cache should evict and not grow unbounded
    for i in 0..10_000 {
        let key = format!("k{i}");
        let ctx = marshall::ExecutionContract::local("counter", &json!({}), reg.policy_identity());
        reg.execute_once(&key, &ctx, "counter", json!({}))
            .await
            .unwrap();
    }
    let len = reg.cache_len().await;
    assert!(len <= 1024, "cache leaked: {len}");
    assert!(len > 0);

    // Re-run same keys with small concurrency to ensure no race leak
    let reg = Arc::new(reg);
    let mut handles = Vec::new();
    for _ in 0..100 {
        let r = reg.clone();
        handles.push(tokio::spawn(async move {
            for i in 0..100 {
                let ctx =
                    marshall::ExecutionContract::local("counter", &json!({}), r.policy_identity());
                r.execute_once(&format!("concur{i}"), &ctx, "counter", json!({}))
                    .await
                    .unwrap();
            }
        }));
    }
    for h in handles {
        h.await.unwrap();
    }
    let len = reg.cache_len().await;
    assert!(len <= 1024, "concurrent leak: {len}");
}
