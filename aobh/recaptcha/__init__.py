"""aobh.recaptcha — CAPTCHA detection, sanctioned solving strategies and
server-side validation-bypass testing (ported from the proven
captcha/captcha_core.py).

Three strategies, in the order the skill mandates (§12):

  human    — DEFAULT. The operator completes the challenge (browser or provided
             session); the tool returns instructions. No circumvention.
  service  — ONLY with two explicit gates: an operator-configured solver key
             (env CAPTCHA_SERVICE_KEY/URL) AND a per-call authorization_reference
             citing where the engagement allows automated solving. Hard-capped
             per engagement (CAPTCHA_MAX_SOLVES, default 5).
  bypass-test — captcha_test_bypass is NOT circumvention: it probes the TARGET's
             own server-side token validation (omit / empty / dummy / replayed
             token). A server that accepts any of these is a real finding.

Sanctioned strategies only: detection, backoff, reuse of an already-
authenticated session, handing the challenge to the operator, and the
operator-configured solver service. No CAPTCHA/anti-bot circumvention.
"""
