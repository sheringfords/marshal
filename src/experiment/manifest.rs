#![allow(missing_docs)]
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TaskCategory {
    #[serde(alias = "repository_investigation")]
    Investigation,
    #[serde(alias = "bug_fix")]
    BugFix,
    #[serde(alias = "small_feature")]
    Feature,
    Refactor,
    #[serde(alias = "test_failure_diagnosis_or_fix")]
    TestFailure,
    #[serde(alias = "configuration_or_dependency")]
    Configuration,
    #[default]
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskSpec {
    pub task_id: String,
    pub title: String,
    pub category: TaskCategory,
    pub description: String,
    #[serde(default)]
    pub repo_or_fixture: String,
    #[serde(default, alias = "repository")]
    pub repository: String,
    #[serde(default)]
    pub base_revision: String,
    #[serde(default)]
    pub complexity: String,
    #[serde(default)]
    pub setup_commands: Vec<String>,
    /// Commands/checks that constitute verification for this task.
    #[serde(default)]
    pub verification_commands_or_checks: Vec<String>,
    pub success_criteria: String,
    #[serde(default)]
    pub expected_files_or_scope: Vec<String>,
    #[serde(default)]
    pub external_dependencies: Vec<String>,
    #[serde(default)]
    pub notes: String,
    #[serde(default)]
    pub validity_constraints: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskManifest {
    pub schema_version: String,
    pub tasks: Vec<TaskSpec>,
}

impl TaskManifest {
    pub fn from_json(s: &str) -> anyhow::Result<Self> {
        let m: Self = serde_json::from_str(s)?;
        m.validate()?;
        Ok(m)
    }
    pub fn from_yaml(s: &str) -> anyhow::Result<Self> {
        let m: Self = serde_yaml::from_str(s)?;
        m.validate()?;
        Ok(m)
    }

    /// Complexity must be empty (unset) or one of simple/medium/complex.
    pub fn validate(&self) -> anyhow::Result<()> {
        for t in &self.tasks {
            if !t.complexity.is_empty()
                && !matches!(t.complexity.as_str(), "simple" | "medium" | "complex")
            {
                anyhow::bail!(
                    "invalid complexity '{}' for task {}: expected simple/medium/complex",
                    t.complexity,
                    t.task_id
                );
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manifest_parse_sample() {
        let json = r#"{
            "schema_version": "validation.v1",
            "tasks": [{
                "task_id": "t1",
                "title": "fix off-by-one",
                "category": "bug_fix",
                "description": "fix loop",
                "repo_or_fixture": "sample",
                "base_revision": "abc",
                "verification_commands_or_checks": ["cargo test"],
                "success_criteria": "tests pass",
                "notes": ""
            }]
        }"#;
        let m = TaskManifest::from_json(json).unwrap();
        assert_eq!(m.tasks.len(), 1);
        assert_eq!(m.tasks[0].category, TaskCategory::BugFix);
    }

    #[test]
    fn invalid_complexity_is_rejected() {
        let json = r#"{
            "schema_version": "validation.v1",
            "tasks": [{
                "task_id": "t1",
                "title": "x",
                "category": "bug_fix",
                "description": "x",
                "complexity": "hard",
                "verification_commands_or_checks": [],
                "success_criteria": "x"
            }]
        }"#;
        assert!(TaskManifest::from_json(json).is_err());
    }
}
