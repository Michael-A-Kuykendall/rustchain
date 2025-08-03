use std::collections::{HashMap, HashSet, VecDeque};

#[derive(Debug, Clone)]
pub struct TaskNode {
    pub id: String,
    pub depends_on: Vec<String>,
    pub params: HashMap<String, String>,
}

pub struct GraphExecutor {
    pub tasks: HashMap<String, TaskNode>,
}

impl GraphExecutor {
    pub fn new() -> Self {
        Self {
            tasks: HashMap::new(),
        }
    }

    pub fn add_task(&mut self, task: TaskNode) {
        self.tasks.insert(task.id.clone(), task);
    }

    pub fn topological_sort(&self) -> Result<Vec<String>, String> {
        let mut in_degree: HashMap<String, usize> = self.tasks
            .keys()
            .map(|id| (id.clone(), 0))
            .collect();

        // Calculate in-degrees
        for task in self.tasks.values() {
            for dep in &task.depends_on {
                if !self.tasks.contains_key(dep) {
                    return Err(format!("Dependency '{}' not found for task '{}'", dep, task.id));
                }
                if let Some(degree) = in_degree.get_mut(&task.id) {
                    *degree += 1;
                }
            }
        }

        let mut queue: VecDeque<String> = in_degree
            .iter()
            .filter(|(_, &degree)| degree == 0)
            .map(|(id, _)| id.clone())
            .collect();

        let mut order = vec![];
        let mut visited = HashSet::new();

        while let Some(node) = queue.pop_front() {
            order.push(node.clone());
            visited.insert(node.clone());

            for t in self.tasks.values() {
                if t.depends_on.contains(&node) {
                    // Safe access instead of unwrap
                    if let Some(entry) = in_degree.get_mut(&t.id) {
                        *entry -= 1;
                        if *entry == 0 {
                            queue.push_back(t.id.clone());
                        }
                    } else {
                        return Err(format!("Task '{}' missing from in_degree map", t.id));
                    }
                }
            }
        }

        if visited.len() != self.tasks.len() {
            let unvisited: Vec<_> = self.tasks.keys()
                .filter(|id| !visited.contains(*id))
                .collect();
            Err(format!("Cycle detected in task graph. Unprocessed tasks: {:?}", unvisited))
        } else {
            Ok(order)
        }
    }
}
