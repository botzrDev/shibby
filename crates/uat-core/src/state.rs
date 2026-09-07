//! Caller and callee state machines (v0.2 §5.4 + Amendment 1 errata).

use crate::codes::{CloseCode, FailureCode};
use crate::message::Message;
use crate::outcome::Outcome;

/// A transition not in the protocol table.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Illegal;

/// Result of a legal step: next state plus an optional message to send.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Step<S> {
    pub state: S,
    pub emit: Option<Message>,
}

impl<S> Step<S> {
    fn go(state: S) -> Self {
        Self { state, emit: None }
    }

    fn emit(state: S, msg: Message) -> Self {
        Self {
            state,
            emit: Some(msg),
        }
    }
}

/// Caller lifecycle. Distinct type from [`CalleeState`] (S7).
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CallerState {
    Dialing,
    Submitted,
    Working,
    AwaitingInput,
    Canceling,
    Terminal(Outcome),
}

impl CallerState {
    #[must_use]
    pub const fn is_terminal(&self) -> bool {
        matches!(self, Self::Terminal(_))
    }
}

/// Events that drive [`caller_step`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CallerEvent {
    Send(Message),
    Recv(Message),
    Timeout,
    ConnLost(CloseCode),
}

/// Callee lifecycle.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CalleeState {
    Offered,
    Working,
    NeedInputSent,
    Terminal(Outcome),
}

impl CalleeState {
    #[must_use]
    pub const fn is_terminal(&self) -> bool {
        matches!(self, Self::Terminal(_))
    }
}

/// Events that drive [`callee_step`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CalleeEvent {
    Send(Message),
    Recv(Message),
    Timeout,
    ConnLost(CloseCode),
}

/// Total function over the caller table. Illegal pairs close with `ProtocolViolation`.
pub fn caller_step(state: CallerState, event: CallerEvent) -> Result<Step<CallerState>, Illegal> {
    use CallerEvent as E;
    use CallerState as S;
    use Message as M;

    if state.is_terminal() {
        return Err(Illegal);
    }

    match (&state, &event) {
        (S::Dialing, E::Send(M::Submit { .. })) => Ok(Step::go(S::Submitted)),

        (S::Submitted, E::Recv(M::Accepted)) => Ok(Step::go(S::Working)),
        (S::Submitted, E::Recv(M::Failed { code })) => {
            Ok(Step::go(S::Terminal(Outcome::Failed(*code))))
        }
        (S::Submitted, E::Send(M::Cancel)) => Ok(Step::go(S::Canceling)),

        (S::Working, E::Recv(M::Progress)) => Ok(Step::go(S::Working)),
        (S::Working, E::Recv(M::NeedInput)) => Ok(Step::go(S::AwaitingInput)),
        (S::Working, E::Recv(M::Completed { .. })) => {
            Ok(Step::go(S::Terminal(Outcome::Completed)))
        }
        (S::Working, E::Recv(M::Failed { code })) => {
            Ok(Step::go(S::Terminal(Outcome::Failed(*code))))
        }
        (S::Working, E::Send(M::Cancel)) => Ok(Step::go(S::Canceling)),

        (S::AwaitingInput, E::Send(M::Input { .. })) => Ok(Step::go(S::Working)),
        (S::AwaitingInput, E::Send(M::Cancel)) => Ok(Step::go(S::Canceling)),
        (S::AwaitingInput, E::Recv(M::Failed { code })) => {
            Ok(Step::go(S::Terminal(Outcome::Failed(*code))))
        }

        // A1.2.1: Canceling may still see Accepted in flight.
        (S::Canceling, E::Recv(M::Accepted)) => Ok(Step::go(S::Canceling)),
        (S::Canceling, E::Recv(M::Canceled)) => Ok(Step::go(S::Terminal(Outcome::Canceled))),
        (S::Canceling, E::Recv(M::Completed { .. })) => {
            Ok(Step::go(S::Terminal(Outcome::Completed)))
        }
        (S::Canceling, E::Recv(M::Failed { code })) => {
            Ok(Step::go(S::Terminal(Outcome::Failed(*code))))
        }
        (S::Canceling, E::Recv(M::Progress | M::NeedInput)) => Ok(Step::go(S::Canceling)),

        (_, E::Timeout) => Ok(Step::go(S::Terminal(Outcome::Closed(CloseCode::Timeout)))),
        (_, E::ConnLost(code)) => Ok(Step::go(conn_lost_outcome_caller(*code))),

        _ => Err(Illegal),
    }
}

fn conn_lost_outcome_caller(code: CloseCode) -> CallerState {
    if code == CloseCode::Normal {
        CallerState::Terminal(Outcome::PeerLost)
    } else {
        CallerState::Terminal(Outcome::Closed(code))
    }
}

/// Total function over the callee table.
pub fn callee_step(state: CalleeState, event: CalleeEvent) -> Result<Step<CalleeState>, Illegal> {
    use CalleeEvent as E;
    use CalleeState as S;
    use Message as M;

    if state.is_terminal() {
        return Err(Illegal);
    }

    match (&state, &event) {
        (S::Offered, E::Send(M::Accepted)) => Ok(Step::go(S::Working)),
        (S::Offered, E::Send(M::Failed { code })) => {
            // A1.2.4: Rejected is harness-only from Offered; other Failed codes also OK here.
            Ok(Step::go(S::Terminal(Outcome::Failed(*code))))
        }
        (S::Offered, E::Recv(M::Cancel)) => Ok(Step::emit(
            S::Terminal(Outcome::Canceled),
            M::Canceled,
        )),

        (S::Working, E::Send(M::Progress)) => Ok(Step::go(S::Working)),
        (S::Working, E::Send(M::NeedInput)) => Ok(Step::go(S::NeedInputSent)),
        (S::Working, E::Send(M::Completed { .. })) => {
            Ok(Step::go(S::Terminal(Outcome::Completed)))
        }
        (S::Working, E::Send(M::Failed { code })) => {
            // Failed{Rejected} after Accepted is a protocol violation (A1.2.4).
            if *code == FailureCode::Rejected {
                return Err(Illegal);
            }
            Ok(Step::go(S::Terminal(Outcome::Failed(*code))))
        }
        (S::Working, E::Recv(M::Cancel)) => Ok(Step::emit(
            S::Terminal(Outcome::Canceled),
            M::Canceled,
        )),

        (S::NeedInputSent, E::Recv(M::Input { .. })) => Ok(Step::go(S::Working)),
        (S::NeedInputSent, E::Recv(M::Cancel)) => Ok(Step::emit(
            S::Terminal(Outcome::Canceled),
            M::Canceled,
        )),
        (S::NeedInputSent, E::Send(M::Failed { code })) => {
            if *code == FailureCode::Rejected {
                return Err(Illegal);
            }
            Ok(Step::go(S::Terminal(Outcome::Failed(*code))))
        }

        (_, E::Timeout) => Ok(Step::emit(
            S::Terminal(Outcome::Failed(FailureCode::DeadlineExceeded)),
            M::Failed {
                code: FailureCode::DeadlineExceeded,
            },
        )),
        (_, E::ConnLost(code)) => Ok(Step::go(conn_lost_outcome_callee(*code))),

        _ => Err(Illegal),
    }
}

fn conn_lost_outcome_callee(code: CloseCode) -> CalleeState {
    if code == CloseCode::Normal {
        CalleeState::Terminal(Outcome::PeerLost)
    } else {
        CalleeState::Terminal(Outcome::Closed(code))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{ContentType, Deadline, TaskId};

    fn submit() -> Message {
        Message::Submit {
            task: TaskId::from_u128(1),
            deadline: Deadline::new(1_000).unwrap(),
            content_type: ContentType::new("text/plain").unwrap(),
            credential: None,
            body: Vec::new(),
        }
    }

    fn input() -> Message {
        Message::Input { body: Vec::new() }
    }

    fn completed() -> Message {
        Message::Completed { body: Vec::new() }
    }

    fn all_messages() -> Vec<Message> {
        vec![
            submit(),
            Message::Accepted,
            Message::Progress,
            Message::NeedInput,
            input(),
            completed(),
            Message::Failed {
                code: FailureCode::HandlerError,
            },
            Message::Failed {
                code: FailureCode::Rejected,
            },
            Message::Cancel,
            Message::Canceled,
        ]
    }

    fn caller_states() -> Vec<CallerState> {
        vec![
            CallerState::Dialing,
            CallerState::Submitted,
            CallerState::Working,
            CallerState::AwaitingInput,
            CallerState::Canceling,
            CallerState::Terminal(Outcome::Completed),
        ]
    }

    fn caller_events() -> Vec<CallerEvent> {
        let mut events = Vec::new();
        for m in all_messages() {
            events.push(CallerEvent::Send(m.clone()));
            events.push(CallerEvent::Recv(m));
        }
        events.push(CallerEvent::Timeout);
        for code in [
            CloseCode::Normal,
            CloseCode::Timeout,
            CloseCode::ProtocolViolation,
        ] {
            events.push(CallerEvent::ConnLost(code));
        }
        events
    }

    fn callee_states() -> Vec<CalleeState> {
        vec![
            CalleeState::Offered,
            CalleeState::Working,
            CalleeState::NeedInputSent,
            CalleeState::Terminal(Outcome::Completed),
        ]
    }

    fn callee_events() -> Vec<CalleeEvent> {
        let mut events = Vec::new();
        for m in all_messages() {
            events.push(CalleeEvent::Send(m.clone()));
            events.push(CalleeEvent::Recv(m));
        }
        events.push(CalleeEvent::Timeout);
        for code in [
            CloseCode::Normal,
            CloseCode::Timeout,
            CloseCode::ProtocolViolation,
        ] {
            events.push(CalleeEvent::ConnLost(code));
        }
        events
    }

    #[test]
    fn caller_table_is_total_over_enumerated_pairs() {
        for state in caller_states() {
            for event in caller_events() {
                let _ = caller_step(state.clone(), event);
            }
        }
    }

    #[test]
    fn callee_table_is_total_over_enumerated_pairs() {
        for state in callee_states() {
            for event in callee_events() {
                let _ = callee_step(state.clone(), event);
            }
        }
    }

    #[test]
    fn a1_2_1_canceling_accepts_accepted() {
        let step = caller_step(
            CallerState::Canceling,
            CallerEvent::Recv(Message::Accepted),
        )
        .expect("legal race");
        assert_eq!(step.state, CallerState::Canceling);
    }

    #[test]
    fn caller_cancel_then_completed_is_completed() {
        let step = caller_step(
            CallerState::Canceling,
            CallerEvent::Recv(completed()),
        )
        .unwrap();
        assert_eq!(step.state, CallerState::Terminal(Outcome::Completed));
    }

    #[test]
    fn every_nonterminal_caller_state_reaches_terminal() {
        for state in caller_states() {
            if state.is_terminal() {
                continue;
            }
            let step = caller_step(state, CallerEvent::Timeout).unwrap();
            assert!(step.state.is_terminal());
        }
    }

    #[test]
    fn every_nonterminal_callee_state_reaches_terminal() {
        for state in callee_states() {
            if state.is_terminal() {
                continue;
            }
            let step = callee_step(state, CalleeEvent::Timeout).unwrap();
            assert!(step.state.is_terminal());
            assert_eq!(
                step.emit,
                Some(Message::Failed {
                    code: FailureCode::DeadlineExceeded
                })
            );
        }
    }

    #[test]
    fn rejected_after_accepted_is_illegal() {
        let err = callee_step(
            CalleeState::Working,
            CalleeEvent::Send(Message::Failed {
                code: FailureCode::Rejected,
            }),
        );
        assert_eq!(err, Err(Illegal));
    }

    #[test]
    fn rejected_from_offered_is_legal() {
        let step = callee_step(
            CalleeState::Offered,
            CalleeEvent::Send(Message::Failed {
                code: FailureCode::Rejected,
            }),
        )
        .unwrap();
        assert_eq!(
            step.state,
            CalleeState::Terminal(Outcome::Failed(FailureCode::Rejected))
        );
    }
}
