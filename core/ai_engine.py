"""
ai_engine.py — ChatGPT-driven autonomous recon engine for AutoRecon.

Flow:
  1. Receive target + list of tools available on the machine.
  2. Send to ChatGPT: mission brief + tools + target.
  3. ChatGPT responds with a JSON action (command to run OR "complete").
  4. AutoRecon executes the command locally, captures output.
  5. Output is sent back to ChatGPT for analysis.
  6. Loop until ChatGPT signals completion or max iterations reached.
  7. Final report (findings, interpretations, remediations) + list of
     suggested tools that are NOT installed but would help.
"""

import json
import logging
import subprocess
from pathlib import Path
from typing import Dict, List, Optional, Tuple

log = logging.getLogger("recon-audit")

# Maximum characters of command output forwarded to the AI in one turn.
# Keeps API costs reasonable while preserving the essential signal.
_MAX_OUTPUT_CHARS = 10_000

# ──────────────────────────────────────────────────────────────────────────────
# System prompt injected as the first message of every conversation
# ──────────────────────────────────────────────────────────────────────────────
_SYSTEM_PROMPT = """\
You are an expert penetration tester and security researcher conducting an \
authorized, scoped security audit. Your goals are:

1. Devise a thorough reconnaissance and vulnerability-assessment plan for the \
   given target (IP, CIDR range, or domain).
2. Execute that plan step by step by issuing shell commands that AutoRecon \
   will run on the assessment machine and return to you.
3. Continuously adapt: analyse every result before deciding the next command.
4. Produce a final, professional audit report with:
   - Executive summary
   - Detailed findings (per host / service)
   - Interpretation of each finding (what it means, severity)
   - Remediation recommendations
   - A list of additional tools NOT currently installed that would allow \
     deeper analysis, with the reason for each.

STRICT RESPONSE FORMAT — respond ONLY with a valid JSON object, no markdown \
fences, no extra text outside the JSON:

{
  "status": "running" | "complete",
  "command": "<single-line shell command to execute, or null>",
  "command_explanation": "<one sentence: why this command, what you expect>",
  "analysis": "<analysis of the previous command output; your reasoning>",
  "suggested_tools": [
    {"name": "<tool>", "reason": "<why it would help, what it can uncover>"}
  ],
  "final_report": "<full markdown report — ONLY when status is complete, else null>"
}

Rules:
- commands must be non-interactive (no pagers, no prompts).
- Prefer read-only / passive commands; avoid destructive actions.
- Pipe verbose tools through `head -n 200` or similar to cap output.
- When you have enough information or all avenues are exhausted, \
  set status to "complete" and fill final_report.
- Only list in suggested_tools tools that are NOT in the provided \
  available-tools list.
"""


def _run_command(command: str, timeout: int = 180) -> Tuple[str, int]:
    """
    Execute a shell command via /bin/bash and return (output, returncode).
    stdout and stderr are merged.  Output is truncated if too large.
    """
    try:
        result = subprocess.run(
            command,
            shell=True,
            capture_output=True,
            text=True,
            timeout=timeout,
            executable="/bin/bash",
        )
        output = (result.stdout or "") + (result.stderr or "")
        if len(output) > _MAX_OUTPUT_CHARS:
            output = (
                output[:_MAX_OUTPUT_CHARS]
                + f"\n[... output truncated at {_MAX_OUTPUT_CHARS} chars ...]"
            )
        return output.strip(), result.returncode
    except subprocess.TimeoutExpired:
        return f"[TIMEOUT] Command exceeded {timeout}s and was killed.", -1
    except Exception as exc:  # noqa: BLE001
        return f"[ERROR] Could not execute command: {exc}", -1


class AIEngine:
    """
    Stateful engine that drives a full security scan via the OpenAI chat API.

    Usage::

        engine = AIEngine(api_key="sk-...", model="gpt-4o")
        result = engine.run(target="192.168.1.1", available_tools={...}, base_dir=Path("results/..."))
    """

    def __init__(
        self,
        api_key: str,
        model: str = "gpt-4o",
        max_iterations: int = 40,
        command_timeout: int = 180,
    ) -> None:
        try:
            from openai import OpenAI  # lazy import — optional dependency
        except ImportError as exc:
            raise ImportError(
                "The 'openai' package is required for AI mode. "
                "Install it with: pip install openai"
            ) from exc

        self._client = OpenAI(api_key=api_key)
        self.model = model
        self.max_iterations = max_iterations
        self.command_timeout = command_timeout
        self._messages: List[Dict] = []
        self._suggested_tools: List[Dict] = []

    # ──────────────────────────────────────────────────────────────────────
    # Internal helpers
    # ──────────────────────────────────────────────────────────────────────

    def _chat(self, user_content: str) -> Dict:
        """Append a user turn, call the API, append the assistant reply."""
        self._messages.append({"role": "user", "content": user_content})
        response = self._client.chat.completions.create(
            model=self.model,
            messages=[
                {"role": "system", "content": _SYSTEM_PROMPT},
                *self._messages,
            ],
            response_format={"type": "json_object"},
            temperature=0.15,
        )
        raw = response.choices[0].message.content or "{}"
        self._messages.append({"role": "assistant", "content": raw})
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            log.warning("[AI] Could not parse JSON response; treating as analysis text.")
            return {
                "status": "running",
                "command": None,
                "command_explanation": "",
                "analysis": raw,
                "suggested_tools": [],
                "final_report": None,
            }

    def _merge_suggested_tools(self, new_items: Optional[List[Dict]]) -> None:
        """Accumulate suggested tools, deduplicating by name."""
        for item in new_items or []:
            name = item.get("name", "").strip()
            if name and not any(t["name"] == name for t in self._suggested_tools):
                self._suggested_tools.append(item)

    # ──────────────────────────────────────────────────────────────────────
    # Public API
    # ──────────────────────────────────────────────────────────────────────

    def run(
        self,
        target: str,
        available_tools: Dict[str, str],
        base_dir: Path,
    ) -> Dict:
        """
        Drive a full AI scan of *target*.

        Returns a dict with:
          - ai_report        (str)  : final markdown report
          - suggested_tools  (list) : tools recommended by AI but not installed
          - iterations       (int)  : number of command/analysis cycles
          - conversation_log (str)  : path to the full JSON conversation log
          - output_dir       (str)  : path to the ai_scan/ folder
        """
        from core.tool_discovery import format_tools_for_prompt  # avoid circular

        tools_str = format_tools_for_prompt(available_tools)
        ai_dir = Path(base_dir) / "ai_scan"
        ai_dir.mkdir(parents=True, exist_ok=True)

        conversation_log: List[Dict] = []
        final_report: Optional[str] = None

        # ── Initial prompt ────────────────────────────────────────────────
        initial_prompt = (
            f"TARGET: {target}\n\n"
            f"TOOLS AVAILABLE ON THIS MACHINE:\n{tools_str}\n\n"
            "YOUR MISSION:\n"
            "Conduct a comprehensive security reconnaissance and vulnerability "
            "assessment of the target above.\n"
            "- Start with passive/low-noise techniques, then escalate.\n"
            "- Enumerate all exposed services, banners, versions.\n"
            "- Test for known misconfigurations and common vulnerabilities.\n"
            "- When you discover an open service, investigate it further.\n"
            "- Track tools NOT in the available-tools list that would help.\n\n"
            "Begin with your action plan summary, then issue your first command."
        )

        log.info("[AI] ══════════════════════════════════════════════")
        log.info("[AI]  Starting AI-driven scan  |  target: %s", target)
        log.info("[AI]  Model: %s  |  Max iterations: %d", self.model, self.max_iterations)
        log.info("[AI] ══════════════════════════════════════════════")

        response = self._chat(initial_prompt)

        # ── Main loop ─────────────────────────────────────────────────────
        iteration = 0
        while iteration < self.max_iterations:
            iteration += 1

            status = response.get("status", "running")
            command: Optional[str] = response.get("command")
            explanation: str = response.get("command_explanation", "")
            analysis: str = response.get("analysis", "")
            self._merge_suggested_tools(response.get("suggested_tools"))

            log.info("[AI] ─── Iteration %d / %d ─── status=%s", iteration, self.max_iterations, status)
            if analysis:
                log.info("[AI] Analysis: %s", analysis[:400])
            if command:
                log.info("[AI] Next command: %s", command)
                log.info("[AI] Reason     : %s", explanation)

            # Record turn (without output yet)
            turn: Dict = {
                "iteration": iteration,
                "status": status,
                "command": command,
                "command_explanation": explanation,
                "analysis": analysis,
                "suggested_tools": response.get("suggested_tools", []),
            }

            # ── Completion check ──────────────────────────────────────────
            if status == "complete" or command is None:
                final_report = response.get("final_report") or analysis
                turn["final_report"] = final_report
                conversation_log.append(turn)
                log.info("[AI] Scan marked complete after %d iteration(s).", iteration)
                break

            # ── Execute command ───────────────────────────────────────────
            log.info("[AI] Executing command …")
            output, rc = _run_command(command, timeout=self.command_timeout)
            log.info("[AI] Exit code: %d | Output: %d chars", rc, len(output))

            # Persist command output to disk
            step_file = ai_dir / f"step_{iteration:03d}.txt"
            step_file.write_text(
                f"COMMAND : {command}\nEXIT CODE: {rc}\n\nOUTPUT:\n{output}",
                encoding="utf-8",
            )

            turn["output"] = output
            turn["exit_code"] = rc
            conversation_log.append(turn)

            # ── Send result back to AI ────────────────────────────────────
            result_msg = (
                f"COMMAND EXECUTED: {command}\n"
                f"EXIT CODE: {rc}\n\n"
                f"OUTPUT:\n{output}\n\n"
                "Analyse the output above. What did you find? What is your next step?"
            )
            response = self._chat(result_msg)

        else:
            # Max iterations exhausted — request final report
            log.info("[AI] Max iterations reached. Requesting final report …")
            response = self._chat(
                "You have reached the maximum number of iterations. "
                "Please compile everything you have found into a final report now. "
                "Set status to 'complete' and populate the final_report field."
            )
            final_report = response.get("final_report") or response.get("analysis", "")
            self._merge_suggested_tools(response.get("suggested_tools"))
            conversation_log.append(
                {
                    "iteration": iteration + 1,
                    "status": "complete",
                    "command": None,
                    "command_explanation": "",
                    "analysis": response.get("analysis", ""),
                    "final_report": final_report,
                    "suggested_tools": response.get("suggested_tools", []),
                }
            )

        # ── Persist artefacts ─────────────────────────────────────────────
        conv_path = ai_dir / "conversation.json"
        conv_path.write_text(
            json.dumps(conversation_log, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
        log.info("[AI] Conversation log saved → %s", conv_path)

        if final_report:
            report_path = ai_dir / "ai_report.md"
            report_path.write_text(final_report, encoding="utf-8")
            log.info("[AI] Final report saved → %s", report_path)

        if self._suggested_tools:
            tools_path = ai_dir / "suggested_tools.json"
            tools_path.write_text(
                json.dumps(self._suggested_tools, indent=2, ensure_ascii=False),
                encoding="utf-8",
            )
            log.info("[AI] Suggested (not installed) tools saved → %s", tools_path)
            log.info("[AI] Tools that could enhance the analysis:")
            for t in self._suggested_tools:
                log.info("[AI]   ✗ %-20s — %s", t.get("name", "?"), t.get("reason", ""))

        log.info("[AI] ══════════════════════════════════════════════")
        log.info("[AI]  AI scan finished  |  %d iteration(s)", iteration)
        log.info("[AI] ══════════════════════════════════════════════")

        return {
            "ai_report": final_report,
            "suggested_tools": self._suggested_tools,
            "iterations": iteration,
            "conversation_log": str(conv_path),
            "output_dir": str(ai_dir),
        }
