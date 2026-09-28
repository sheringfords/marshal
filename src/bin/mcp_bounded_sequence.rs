#![allow(missing_docs)]
use serde_json::{json, Value};
use std::io::{BufRead, Write};
use std::path::Path;
use std::sync::Arc;

use marshall::{
    shell::AllowedCommand, ArgumentPolicy, ContractedCall, FileSystemTool, Sandbox, ShellTool,
    ToolRegistry,
};

fn create_registry() -> anyhow::Result<ToolRegistry> {
    let cwd = std::env::current_dir()?;
    let sandbox = Sandbox::new([&cwd])?;
    let fs = FileSystemTool::new(sandbox.clone()).writable();
    let echo = if Path::new("/bin/echo").exists() {
        "/bin/echo"
    } else {
        "/usr/bin/echo"
    };
    let cat = if Path::new("/bin/cat").exists() {
        "/bin/cat"
    } else {
        "/usr/bin/cat"
    };
    // allow git as well for real tasks
    let git = if Path::new("/usr/bin/git").exists() {
        "/usr/bin/git"
    } else {
        "/bin/git"
    };
    let shell = ShellTool::new(vec![
        AllowedCommand::new(echo).with_arguments(ArgumentPolicy::NoFlags),
        AllowedCommand::new(cat).with_arguments(ArgumentPolicy::NoFlags),
        AllowedCommand::new(git).with_arguments(ArgumentPolicy::NoFlags),
    ])
    .with_working_dirs(sandbox);
    let mut reg = ToolRegistry::new();
    reg.register(Arc::new(fs));
    reg.register(Arc::new(shell));
    // HttpTool not needed for this benchmark
    Ok(reg)
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Log startup
    let _ = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open("/tmp/mcp_bounded.log")
        .and_then(|mut f| {
            use std::io::Write;
            writeln!(
                f,
                "mcp_bounded_sequence started at {:?}",
                std::time::SystemTime::now()
            )
        });
    let stdin = std::io::stdin();
    let mut stdout = std::io::stdout();
    let mut reader = std::io::BufReader::new(stdin.lock());
    let mut line = String::new();
    while reader.read_line(&mut line)? != 0 {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            line.clear();
            continue;
        }
        let req: Value = match serde_json::from_str(trimmed) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("mcp parse error: {e}");
                line.clear();
                continue;
            }
        };
        let id = req.get("id").cloned();
        let method = req.get("method").and_then(|v| v.as_str()).unwrap_or("");
        let params = req.get("params").cloned().unwrap_or(Value::Null);

        let mut response = json!({"jsonrpc":"2.0"});
        if let Some(i) = id.clone() {
            response["id"] = i;
        }

        match method {
            "initialize" => {
                let req_ver = params
                    .get("protocolVersion")
                    .and_then(|v| v.as_str())
                    .unwrap_or("2024-11-05");
                response["result"] = json!({
                    "protocolVersion": req_ver,
                    "capabilities": {"tools": {"listChanged": false}},
                    "serverInfo": {"name": "bounded_sequence", "version": "0.1.0"}
                });
                writeln!(stdout, "{}", serde_json::to_string(&response)?)?;
                stdout.flush()?;
            }
            "notifications/initialized" => {
                // no response
            }
            "tools/list" => {
                response["result"] = json!({
                    "tools": [
                    {
                        "name": "bounded_sequence",
                        "description": "Execute 2 or 3 deterministic tool operations sequentially as one invocation. Stops on the first failure and returns structured per-step evidence. Use only when you do not need additional reasoning between those operations. Each step is {\"tool\":\"filesystem\" or \"shell\", \"args\":{...}}. For filesystem: {\"operation\":\"read\"|\"write\"|\"search\"|\"list\"|\"stat\", \"path\":\"...\"}. For shell: {\"program\":\"/bin/echo\", \"args\":[\"...\"]}. Example: {\"steps\":[{\"tool\":\"filesystem\",\"args\":{\"operation\":\"read\",\"path\":\"src/lib.rs\"}}, {\"tool\":\"filesystem\",\"args\":{\"operation\":\"read\",\"path\":\"src/sandbox.rs\"}}]}",
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "steps": {
                                    "type": "array",
                                    "minItems": 2,
                                    "maxItems": 3,
                                    "items": {
                                        "type": "object",
                                        "properties": {
                                            "tool": {"type":"string", "enum": ["filesystem","shell"]},
                                            "args": {"type":"object"}
                                        },
                                        "required": ["tool","args"]
                                    }
                                }
                            },
                            "required": ["steps"]
                        }
                    }
                    ]
                });
                writeln!(stdout, "{}", serde_json::to_string(&response)?)?;
                stdout.flush()?;
            }
            "tools/call" => {
                let name = params.get("name").and_then(|v| v.as_str()).unwrap_or("");
                if name != "bounded_sequence" {
                    response["error"] = json!({"code": -32601, "message": "unknown tool"});
                    writeln!(stdout, "{}", serde_json::to_string(&response)?)?;
                    stdout.flush()?;
                    line.clear();
                    continue;
                }
                let args = params.get("arguments").cloned().unwrap_or(Value::Null);
                let steps_val = args.get("steps").and_then(|v| v.as_array());
                let steps_val = match steps_val {
                    Some(s) => s.clone(),
                    None => {
                        response["result"] = json!({"content": [{"type":"text","text": "error: missing steps"}], "isError": true});
                        writeln!(stdout, "{}", serde_json::to_string(&response)?)?;
                        stdout.flush()?;
                        line.clear();
                        continue;
                    }
                };
                if steps_val.len() < 2 || steps_val.len() > 3 {
                    response["result"] = json!({"content": [{"type":"text","text": format!("error: bounded_sequence requires 2-3 steps, got {}", steps_val.len())}], "isError": true});
                    writeln!(stdout, "{}", serde_json::to_string(&response)?)?;
                    stdout.flush()?;
                    line.clear();
                    continue;
                }
                // Build registry and execute
                let reg = match create_registry() {
                    Ok(r) => r,
                    Err(e) => {
                        response["result"] = json!({"content": [{"type":"text","text": format!("registry error: {}", e)}], "isError": true});
                        writeln!(stdout, "{}", serde_json::to_string(&response)?)?;
                        stdout.flush()?;
                        line.clear();
                        continue;
                    }
                };
                let mut steps: Vec<(String, Value)> = Vec::new();
                for s in &steps_val {
                    let tool = s
                        .get("tool")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string();
                    let a = s.get("args").cloned().unwrap_or(Value::Null);
                    steps.push((tool, a));
                }
                // Execute via bounded_sequence logic (reuse treatment.rs if available, else direct).
                // Explicit trusted-local calls: no HTTP admission on this path.
                let contracted: Vec<ContractedCall> = steps
                    .iter()
                    .map(|(tool, a)| ContractedCall::local(&reg, tool, a.clone()))
                    .collect();
                let res = reg.execute_sequence(contracted, false).await;
                // Build compact result
                let mut per_step = Vec::new();
                let mut success = true;
                for r in &res {
                    match r {
                        Ok(o) => {
                            if !o.success {
                                success = false;
                            }
                            per_step.push(json!({"tool": o.tool, "success": o.success, "error_code": o.error_code, "duration_ms": o.duration_ms, "output_bytes": o.content.as_ref().map(|b| b.len()).unwrap_or(0)}));
                        }
                        Err(e) => {
                            success = false;
                            per_step.push(json!({"error": e.to_string()}));
                        }
                    }
                }
                // If res len < requested, it stopped early
                if res.len() < steps_val.len() {
                    success = false;
                }
                let result_text = serde_json::to_string_pretty(&json!({
                    "sequence_success": success,
                    "requested_steps": steps_val.len(),
                    "executed_steps": res.len(),
                    "per_step": per_step
                }))?;
                response["result"] = json!({"content": [{"type":"text","text": result_text}]});
                writeln!(stdout, "{}", serde_json::to_string(&response)?)?;
                stdout.flush()?;
            }
            "ping" => {
                response["result"] = json!({});
                writeln!(stdout, "{}", serde_json::to_string(&response)?)?;
                stdout.flush()?;
            }
            _ => {
                // ignore or error
                if id.is_some() {
                    response["error"] =
                        json!({"code": -32601, "message": format!("unknown method {}", method)});
                    writeln!(stdout, "{}", serde_json::to_string(&response)?)?;
                    stdout.flush()?;
                }
            }
        }
        line.clear();
    }
    Ok(())
}
