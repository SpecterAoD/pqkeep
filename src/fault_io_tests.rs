//! DE: Nur im Lib-Testbinary: isolierte, explizit verbrauchte I/O-Pläne ohne Inhaltsprotokolle.
//! EN: Lib test binary only: isolated, explicitly consumed I/O plans without content logging.
#![allow(clippy::unwrap_used, clippy::panic)]

use std::cell::RefCell;
use std::io::{self, ErrorKind};
use std::path::{Component, Path, PathBuf};
use std::rc::Rc;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Point {
    BeforeOpen,
    AfterTempCreate,
    Write,
    BeforeFlush,
    BeforeFileSync,
    BeforePublish,
    AfterPublish,
}

#[derive(Clone, Copy)]
pub(crate) enum Failure {
    Kind(ErrorKind),
    Os(i32),
}

impl Failure {
    pub(crate) fn error(self) -> io::Error {
        match self {
            Self::Kind(kind) => kind.into(),
            Self::Os(code) => io::Error::from_raw_os_error(code),
        }
    }
}

#[derive(Clone, Copy)]
pub(crate) enum Action {
    Fail(Failure),
    Partial { after: usize, failure: Failure },
    Short(usize),
    Interrupt,
    Zero,
}

#[derive(Clone, Copy)]
pub(crate) struct Plan {
    pub point: Point,
    pub occurrence: usize,
    pub action: Action,
}

pub(crate) struct State {
    root: PathBuf,
    plan: Plan,
    seen: usize,
    consumed: bool,
    active: bool,
    trace: Vec<Point>,
}

pub(crate) type Shared = Rc<RefCell<State>>;

thread_local! {
    static CURRENT: RefCell<Option<Shared>> = const { RefCell::new(None) };
}

pub(crate) struct Scope(Shared);

impl Scope {
    pub(crate) fn new(root: &Path, plan: Plan) -> Self {
        assert!(plan.occurrence > 0, "Fault occurrence / Fehlervorkommen");
        assert!(root.is_absolute() && root.symlink_metadata().unwrap().is_dir());
        assert!(matches!(plan.action, Action::Fail(_)) || plan.point == Point::Write);
        assert!(!matches!(plan.action, Action::Short(0)));
        let state = Rc::new(RefCell::new(State {
            root: root.canonicalize().unwrap(),
            plan,
            seen: 0,
            consumed: false,
            active: true,
            trace: Vec::new(),
        }));
        CURRENT.with(|current| {
            let mut slot = current.borrow_mut();
            assert!(
                slot.is_none(),
                "Nested fault plan / Verschachtelter Fehlerplan"
            );
            *slot = Some(state.clone());
        });
        Self(state)
    }

    pub(crate) fn finish(self) -> Vec<Point> {
        assert!(
            self.0.borrow().consumed,
            "Unreached fault / Fehlerpunkt nicht erreicht"
        );
        let trace = self.0.borrow().trace.clone();
        drop(self);
        trace
    }
}

impl Drop for Scope {
    fn drop(&mut self) {
        self.0.borrow_mut().active = false;
        CURRENT.with(|current| {
            let mut slot = current.borrow_mut();
            if slot.as_ref().is_some_and(|s| Rc::ptr_eq(s, &self.0)) {
                *slot = None;
            }
        });
        // DE: Beim Unwinding keine zweite Panik. EN: No second panic during unwinding.
        assert!(
            self.0.borrow().consumed || std::thread::panicking(),
            "Unused fault / Unverbrauchter Fehler"
        );
    }
}

pub(crate) fn capture(path: &Path) -> Option<Shared> {
    if !path.is_absolute() || path.components().any(|c| c == Component::ParentDir) {
        return None;
    }
    let parent = path.parent()?.canonicalize().ok()?;
    CURRENT.with(|current| {
        current
            .borrow()
            .as_ref()
            .filter(|s| parent.starts_with(&s.borrow().root))
            .cloned()
    })
}

pub(crate) fn action(state: &Shared, point: Point) -> Option<Action> {
    let mut state = state.borrow_mut();
    if !state.active {
        return None;
    }
    state.trace.push(point);
    if state.plan.point != point || state.consumed {
        return None;
    }
    state.seen += 1;
    (state.seen >= state.plan.occurrence).then_some(state.plan.action)
}

pub(crate) fn consume(state: &Shared) {
    state.borrow_mut().consumed = true;
}

pub(crate) fn check_state(state: &Shared, point: Point) -> io::Result<()> {
    match action(state, point) {
        None => Ok(()),
        Some(Action::Fail(failure)) => {
            consume(state);
            Err(failure.error())
        }
        Some(_) => panic!("Invalid fault point / Ungültiger Fehlerpunkt"),
    }
}

pub(crate) fn checkpoint(path: &Path, point: Point) -> io::Result<()> {
    capture(path).map_or(Ok(()), |s| check_state(&s, point))
}
