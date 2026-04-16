/*
 * auth_model.pml — Promela Model for MiniBank Authentication State Machine
 * =========================================================================
 *
 * States:
 *   UNAUTHENTICATED (0) — Initial state; user has not yet attempted login.
 *   AUTHENTICATED   (1) — User has successfully logged in.
 *   LOCKED          (2) — Account locked after 3 consecutive failed attempts.
 *
 * Transitions:
 *   UNAUTHENTICATED --[attempt_login]--> UNAUTHENTICATED (wrong password, attempts < 3)
 *   UNAUTHENTICATED --[attempt_login]--> LOCKED          (3rd wrong password)
 *   UNAUTHENTICATED --[correct_login]--> AUTHENTICATED
 *   AUTHENTICATED   --[logout]       --> UNAUTHENTICATED
 *   LOCKED          (terminal — no transitions out without admin reset)
 *
 * LTL Properties verified:
 *   P1: [] (authenticated -> previously_attempted_login)
 *       "It is always the case that a user can only be AUTHENTICATED if they
 *        previously went through the login attempt process."
 *
 *   P2: [] !(authenticated && locked)
 *       "A user can never be simultaneously AUTHENTICATED and LOCKED."
 *
 * Model Checking (manual exhaustive state enumeration also provided below).
 */

/* State encoding */
#define UNAUTHENTICATED 0
#define AUTHENTICATED   1
#define LOCKED          2

/* Global state variables */
byte state = UNAUTHENTICATED;   /* current authentication state */
byte failed_attempts = 0;       /* number of consecutive failed logins */
bool attempted_login = false;   /* whether login has ever been attempted */

/* LTL property helper aliases */
#define authenticated  (state == AUTHENTICATED)
#define locked         (state == LOCKED)

/* -----------------------------------------------------------------------
 * LTL Properties
 * -----------------------------------------------------------------------
 * P1: Globally, authenticated implies previously_attempted_login
 *     ltl p1 { [] (authenticated -> attempted_login) }
 *
 * P2: Globally, NOT (authenticated AND locked)
 *     ltl p2 { [] !(authenticated && locked) }
 */
ltl p1 { [] (authenticated -> attempted_login) }
ltl p2 { [] !(authenticated && locked) }

/* -----------------------------------------------------------------------
 * Process: Authentication State Machine
 * ----------------------------------------------------------------------- */
active proctype AuthMachine() {
    do
    :: /* Case 1: Attempt login while UNAUTHENTICATED */
       (state == UNAUTHENTICATED) ->
           attempted_login = true;
           if
           :: /* Correct password — transition to AUTHENTICATED */
              true ->
                  state = AUTHENTICATED;
                  failed_attempts = 0;
           :: /* Wrong password — increment counter */
              true ->
                  failed_attempts = failed_attempts + 1;
                  if
                  :: (failed_attempts >= 3) ->
                         state = LOCKED;
                  :: (failed_attempts < 3) ->
                         skip; /* remain UNAUTHENTICATED */
                  fi
           fi

    :: /* Case 2: Logout while AUTHENTICATED */
       (state == AUTHENTICATED) ->
           state = UNAUTHENTICATED;
           failed_attempts = 0;

    :: /* Case 3: Account is LOCKED — terminal state */
       (state == LOCKED) ->
           break; /* no further transitions */
    od
}

/*
 * ==========================================================================
 * Manual Exhaustive State Enumeration (for environments without SPIN)
 * ==========================================================================
 *
 * Reachable States:
 * -----------------
 * ID | state           | failed_attempts | attempted_login | Reachable? | Notes
 * ---+-----------------+-----------------+-----------------+------------+-------
 *  1 | UNAUTHENTICATED | 0               | false           | YES        | Initial
 *  2 | UNAUTHENTICATED | 1               | true            | YES        | 1 wrong attempt
 *  3 | UNAUTHENTICATED | 2               | true            | YES        | 2 wrong attempts
 *  4 | AUTHENTICATED   | 0               | true            | YES        | Successful login
 *  5 | LOCKED          | 3               | true            | YES        | 3 wrong attempts
 *  6 | UNAUTHENTICATED | 0               | true            | YES        | After logout
 *  7 | AUTHENTICATED   | 0               | false           | NO*        | Impossible: must attempt first
 *  8 | LOCKED          | 0               | false           | NO*        | Impossible: must attempt first
 *  9 | AUTHENTICATED   | *               | *               | NO**       | + locked => impossible by P2
 *
 * Notes:
 *   * States 7 and 8 are unreachable because `attempted_login` is set to
 *     `true` before any state transition from UNAUTHENTICATED can occur.
 *     This proves P1: authenticated -> attempted_login is always satisfied.
 *
 *   ** State 9 (authenticated AND locked simultaneously) is unreachable
 *     because the AUTHENTICATED and LOCKED states are distinct values of
 *     the `state` byte variable — a variable cannot hold two values at once.
 *     This proves P2: !(authenticated && locked) trivially holds.
 *
 * Property Verification Summary:
 * --------------------------------
 * P1 [[] (authenticated -> attempted_login)]:
 *   - Every path to state=AUTHENTICATED passes through the attempted_login=true
 *     assignment. No path exists to AUTHENTICATED without setting attempted_login.
 *   - RESULT: VERIFIED (no counterexample exists)
 *
 * P2 [[] !(authenticated && locked)]:
 *   - `state` is a single-valued variable. It is impossible for state==AUTHENTICATED
 *     and state==LOCKED to be simultaneously true.
 *   - RESULT: VERIFIED (trivially, by mutual exclusion of enum values)
 *
 * SPIN Invocation Commands (run when SPIN is available):
 *   spin -a auth_model.pml
 *   gcc -o pan pan.c
 *   ./pan -a -f          # verify all LTL properties with full state exploration
 *
 * Expected SPIN output:
 *   Verification of never claim (p1): No errors found.
 *   Verification of never claim (p2): No errors found.
 * ==========================================================================
 */
