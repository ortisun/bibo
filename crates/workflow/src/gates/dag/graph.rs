//! The dependency graph of a plan: whether it is a graph that can be run, the order to run it in,
//! which tasks could run at the same time, and the longest chain.
//!
//! Everything here is a function of the plan alone. Ties are broken by the order the plan lists
//! its tasks, so the same plan always gives the same order and the same critical path.

use std::collections::BTreeMap;

/// What is wrong with the shape of the graph.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ShapeProblem {
    /// Two tasks share an identifier.
    Duplicate(String),
    /// A task lists itself as a dependency.
    SelfDependency(String),
    /// A task depends on an identifier the plan does not hold.
    Dangling {
        /// The task.
        task: String,
        /// The identifier it names.
        missing: String,
    },
    /// The dependencies form a cycle. The tasks are those that could not be put in order, in the
    /// order the plan lists them.
    Cycle(Vec<String>),
}

/// One task as the graph needs it.
#[derive(Debug, Clone)]
pub struct Node {
    /// The task identifier.
    pub id: String,
    /// The identifiers it depends on, as written.
    pub depends_on: Vec<String>,
    /// How long it is expected to take, in seconds. It weighs the critical path.
    pub seconds: u64,
}

/// A graph that has been checked: unique identifiers, no dangling edge, no cycle.
#[derive(Debug, Clone)]
pub struct Graph {
    ids: Vec<String>,
    deps: Vec<Vec<usize>>,
    seconds: Vec<u64>,
    order: Vec<usize>,
    /// `below[i][j]` is true when task `i` depends on task `j`, directly or through others.
    below: Vec<Vec<bool>>,
}

/// The longest chain of dependencies.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CriticalPath {
    /// The task identifiers from the first task to run to the last, in order.
    pub tasks: Vec<String>,
    /// The sum of the expected seconds along the chain.
    pub seconds: u64,
}

impl Graph {
    /// Checks the nodes and builds the graph.
    ///
    /// # Errors
    /// Every [`ShapeProblem`] found. A duplicate identifier, a dangling dependency and a
    /// self-dependency are all reported together. A cycle is reported only when the rest of the
    /// shape is sound, because the other problems make "the cycle" ambiguous.
    pub fn build(nodes: &[Node]) -> Result<Self, Vec<ShapeProblem>> {
        let mut problems = Vec::new();
        let mut index: BTreeMap<&str, usize> = BTreeMap::new();
        for (position, node) in nodes.iter().enumerate() {
            if index.insert(node.id.as_str(), position).is_some() {
                problems.push(ShapeProblem::Duplicate(node.id.clone()));
            }
        }
        let mut deps: Vec<Vec<usize>> = Vec::with_capacity(nodes.len());
        for node in nodes {
            let mut list = Vec::new();
            for name in &node.depends_on {
                if name == &node.id {
                    problems.push(ShapeProblem::SelfDependency(node.id.clone()));
                } else if let Some(position) = index.get(name.as_str()) {
                    list.push(*position);
                } else {
                    problems.push(ShapeProblem::Dangling {
                        task: node.id.clone(),
                        missing: name.clone(),
                    });
                }
            }
            deps.push(list);
        }
        if !problems.is_empty() {
            return Err(problems);
        }
        let order = match topological(&deps) {
            Ok(order) => order,
            Err(left_over) => {
                let names = left_over
                    .into_iter()
                    .filter_map(|at| nodes.get(at).map(|node| node.id.clone()))
                    .collect();
                return Err(vec![ShapeProblem::Cycle(names)]);
            }
        };
        let below = closure(&deps, &order);
        Ok(Self {
            ids: nodes.iter().map(|node| node.id.clone()).collect(),
            deps,
            seconds: nodes.iter().map(|node| node.seconds).collect(),
            order,
            below,
        })
    }

    /// The task identifiers in an order that runs every task after the tasks it depends on. Among
    /// tasks that are ready together, the plan's own order decides.
    #[must_use]
    pub fn order(&self) -> Vec<&str> {
        self.order
            .iter()
            .filter_map(|at| self.ids.get(*at).map(String::as_str))
            .collect()
    }

    /// True when the task at `later` depends on the task at `earlier`, directly or not.
    #[must_use]
    pub fn depends(&self, later: usize, earlier: usize) -> bool {
        self.below
            .get(later)
            .and_then(|row| row.get(earlier))
            .copied()
            .unwrap_or(false)
    }

    /// True when one of the two tasks depends on the other, so they never run at the same time.
    #[must_use]
    pub fn ordered(&self, a: usize, b: usize) -> bool {
        self.depends(a, b) || self.depends(b, a)
    }

    /// Every pair of tasks that nothing orders, as positions in the plan with the lower first.
    #[must_use]
    pub fn unordered_pairs(&self) -> Vec<(usize, usize)> {
        let mut pairs = Vec::new();
        for a in 0..self.ids.len() {
            for b in (a + 1)..self.ids.len() {
                if !self.ordered(a, b) {
                    pairs.push((a, b));
                }
            }
        }
        pairs
    }

    /// The task identifier at a position of the plan.
    #[must_use]
    pub fn id(&self, at: usize) -> &str {
        self.ids.get(at).map_or("", String::as_str)
    }

    /// The longest chain of dependencies, weighed by expected seconds. When two chains weigh the
    /// same, the one whose last task the plan lists first wins, and at every step the earlier
    /// listed predecessor.
    #[must_use]
    pub fn critical_path(&self) -> CriticalPath {
        let mut best: Vec<u64> = vec![0; self.ids.len()];
        let mut before: Vec<Option<usize>> = vec![None; self.ids.len()];
        for at in &self.order {
            let own = self.seconds.get(*at).copied().unwrap_or(0);
            let mut pick: Option<usize> = None;
            let mut pick_weight = 0_u64;
            if let Some(list) = self.deps.get(*at) {
                for dependency in list {
                    let weight = best.get(*dependency).copied().unwrap_or(0);
                    let better = match pick {
                        None => true,
                        Some(chosen) => {
                            weight > pick_weight || (weight == pick_weight && *dependency < chosen)
                        }
                    };
                    if better {
                        pick = Some(*dependency);
                        pick_weight = weight;
                    }
                }
            }
            if let Some(slot) = best.get_mut(*at) {
                *slot = own.saturating_add(pick_weight);
            }
            if let Some(slot) = before.get_mut(*at) {
                *slot = pick;
            }
        }
        let mut last: Option<usize> = None;
        for (at, weight) in best.iter().enumerate() {
            let better = match last {
                None => true,
                Some(chosen) => *weight > best.get(chosen).copied().unwrap_or(0),
            };
            if better {
                last = Some(at);
            }
        }
        let seconds = last.and_then(|at| best.get(at).copied()).unwrap_or(0);
        let mut chain = Vec::new();
        let mut cursor = last;
        while let Some(at) = cursor {
            chain.push(self.id(at).to_owned());
            cursor = before.get(at).copied().flatten();
        }
        chain.reverse();
        CriticalPath {
            tasks: chain,
            seconds,
        }
    }
}

/// Kahn's algorithm with the plan's order as the tie-break. `Err` holds the tasks that could not
/// be placed, which are the tasks on a cycle or waiting for one.
fn topological(deps: &[Vec<usize>]) -> Result<Vec<usize>, Vec<usize>> {
    let mut placed = vec![false; deps.len()];
    let mut order = Vec::with_capacity(deps.len());
    while order.len() < deps.len() {
        let next = (0..deps.len()).find(|at| {
            !placed.get(*at).copied().unwrap_or(true)
                && deps.get(*at).is_some_and(|list| {
                    list.iter()
                        .all(|dependency| placed.get(*dependency).copied().unwrap_or(false))
                })
        });
        let Some(at) = next else {
            let left = (0..deps.len())
                .filter(|at| !placed.get(*at).copied().unwrap_or(true))
                .collect();
            return Err(left);
        };
        if let Some(slot) = placed.get_mut(at) {
            *slot = true;
        }
        order.push(at);
    }
    Ok(order)
}

fn closure(deps: &[Vec<usize>], order: &[usize]) -> Vec<Vec<bool>> {
    let count = deps.len();
    let mut below = vec![vec![false; count]; count];
    // In dependency order every task's dependencies are already complete rows.
    for at in order {
        let mut row = vec![false; count];
        if let Some(list) = deps.get(*at) {
            for dependency in list {
                if let Some(cell) = row.get_mut(*dependency) {
                    *cell = true;
                }
                if let Some(inner) = below.get(*dependency) {
                    for (cell, set) in row.iter_mut().zip(inner) {
                        *cell = *cell || *set;
                    }
                }
            }
        }
        if let Some(slot) = below.get_mut(*at) {
            *slot = row;
        }
    }
    below
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node(id: &str, depends_on: &[&str], seconds: u64) -> Node {
        Node {
            id: id.to_owned(),
            depends_on: depends_on.iter().map(|d| (*d).to_owned()).collect(),
            seconds,
        }
    }

    #[test]
    fn a_plan_listed_backwards_still_runs_dependencies_first() {
        let graph = Graph::build(&[
            node("c", &["b"], 1),
            node("b", &["a"], 1),
            node("a", &[], 1),
        ])
        .expect("a graph");
        assert_eq!(graph.order(), ["a", "b", "c"]);
    }

    #[test]
    fn a_cycle_a_dangling_edge_a_duplicate_and_a_self_loop_are_found() {
        let cycle = Graph::build(&[
            node("a", &["b"], 1),
            node("b", &["a"], 1),
            node("c", &[], 1),
        ])
        .expect_err("a cycle");
        assert_eq!(
            cycle,
            vec![ShapeProblem::Cycle(vec!["a".into(), "b".into()])]
        );
        let dangling = Graph::build(&[node("a", &["ghost"], 1)]).expect_err("dangling");
        assert!(matches!(
            dangling.as_slice(),
            [ShapeProblem::Dangling { .. }]
        ));
        let duplicate = Graph::build(&[node("a", &[], 1), node("a", &[], 1)]).expect_err("dup");
        assert_eq!(duplicate, vec![ShapeProblem::Duplicate("a".into())]);
        let own = Graph::build(&[node("a", &["a"], 1)]).expect_err("self");
        assert_eq!(own, vec![ShapeProblem::SelfDependency("a".into())]);
    }

    #[test]
    fn tasks_that_nothing_orders_are_the_parallel_ones() {
        let graph = Graph::build(&[
            node("root", &[], 1),
            node("left", &["root"], 1),
            node("right", &["root"], 1),
            node("join", &["left", "right"], 1),
        ])
        .expect("a graph");
        assert_eq!(graph.unordered_pairs(), vec![(1, 2)]);
        assert!(
            graph.depends(3, 0),
            "a join depends on the root through both"
        );
        assert!(!graph.depends(0, 3));
    }

    #[test]
    fn the_critical_path_is_the_heaviest_chain_and_ties_follow_the_plan_order() {
        let graph = Graph::build(&[
            node("root", &[], 10),
            node("quick", &["root"], 5),
            node("slow", &["root"], 50),
            node("end", &["quick", "slow"], 10),
        ])
        .expect("a graph");
        let path = graph.critical_path();
        assert_eq!(path.tasks, ["root", "slow", "end"]);
        assert_eq!(path.seconds, 70);

        let tie = Graph::build(&[node("first", &[], 5), node("second", &[], 5)]).expect("a graph");
        assert_eq!(tie.critical_path().tasks, ["first"]);
    }
}
