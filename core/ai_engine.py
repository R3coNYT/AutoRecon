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


def _convert_md_to_pdf(md_path: Path, pdf_path: Path) -> None:
    """
    Convert a Markdown file to PDF.
    Strategy (tries in order):
      1. weasyprint  (pip install weasyprint markdown)
      2. pandoc      (system binary)
    Fails silently with a warning — the .md file is always preserved.
    """
    # ── Strategy 1: weasyprint ────────────────────────────────────────────
    try:
        import markdown as _md
        from weasyprint import HTML as _HTML

        css = """
        @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700&display=swap');
        * { box-sizing: border-box; }
        body {
            font-family: 'Inter', 'Segoe UI', Arial, sans-serif;
            font-size: 13px; line-height: 1.7;
            color: #1a1a2e; background: #ffffff;
            margin: 0; padding: 0;
        }
        .page { max-width: 860px; margin: 0 auto; padding: 48px 56px; }
        h1 { font-size: 26px; font-weight: 700; color: #0d1b2a;
             border-bottom: 3px solid #e63946; padding-bottom: 10px; margin-top: 0; }
        h2 { font-size: 18px; font-weight: 700; color: #1d3557;
             border-left: 4px solid #457b9d; padding-left: 10px; margin-top: 32px; }
        h3 { font-size: 14px; font-weight: 700; color: #2c3e50; margin-top: 20px; }
        h4 { font-size: 13px; font-weight: 600; color: #555; margin-top: 14px; }
        p  { margin: 8px 0; }
        code {
            background: #f0f4f8; border-radius: 4px;
            padding: 2px 6px; font-family: 'Courier New', monospace; font-size: 12px;
        }
        pre {
            background: #1e2a38; color: #cdd9e5; border-radius: 6px;
            padding: 14px 18px; overflow-x: auto; font-size: 11.5px;
            border-left: 4px solid #457b9d;
        }
        pre code { background: transparent; color: inherit; padding: 0; }
        blockquote {
            border-left: 4px solid #e63946; background: #fff5f5;
            margin: 12px 0; padding: 8px 16px; color: #555;
        }
        table { width: 100%; border-collapse: collapse; margin: 16px 0; }
        th { background: #1d3557; color: #fff; padding: 8px 12px; text-align: left; font-size: 12px; }
        td { padding: 7px 12px; border-bottom: 1px solid #dde3ea; font-size: 12px; }
        tr:nth-child(even) td { background: #f7f9fc; }
        ul, ol { padding-left: 24px; margin: 8px 0; }
        li { margin: 4px 0; }
        a  { color: #457b9d; text-decoration: none; }
        hr { border: none; border-top: 1px solid #dde3ea; margin: 28px 0; }
        /* severity badges */
        strong { color: #1a1a2e; }
        """
        md_text = md_path.read_text(encoding="utf-8")
        html_body = _md.markdown(
            md_text,
            extensions=["tables", "fenced_code", "toc", "nl2br"],
        )
        html_full = f"""<!DOCTYPE html>
<html lang="fr"><head>
<meta charset="UTF-8">
<style>{css}</style>
</head><body><div class="page">{html_body}</div></body></html>"""
        _HTML(string=html_full).write_pdf(str(pdf_path))
        return
    except ImportError:
        pass
    except Exception as exc:
        log.warning("[AI] weasyprint PDF conversion failed: %s", exc)

    # ── Strategy 2: pandoc ────────────────────────────────────────────────
    import shutil as _shutil
    if _shutil.which("pandoc"):
        try:
            subprocess.run(
                ["pandoc", str(md_path), "-o", str(pdf_path),
                 "--pdf-engine=xelatex", "-V", "geometry:margin=2cm",
                 "-V", "fontsize=11pt"],
                capture_output=True,
                timeout=60,
                check=True,
            )
            return
        except Exception as exc:
            log.warning("[AI] pandoc PDF conversion failed: %s", exc)

    log.warning(
        "[AI] Could not convert ai_report.md to PDF. "
        "Install weasyprint+markdown: pip install weasyprint markdown"
    )


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
        full_scan: bool = False,
        report_language: str = "english",
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
        scope_note = (
            "SCAN SCOPE: FULL — scan ALL 65535 TCP ports (use -p- with nmap). "
            "Do not limit to top ports. Enumerate every open port thoroughly."
            if full_scan else
            "SCAN SCOPE: STANDARD — focus on the most common/interesting ports "
            "(top 1000 TCP). Escalate only if warranted by findings."
        )
        lang = (report_language or "english").strip()
        initial_prompt = (
            f"TARGET: {target}\n\n"
            f"{scope_note}\n\n"
            f"TOOLS AVAILABLE ON THIS MACHINE:\n{tools_str}\n\n"
            f"REPORT LANGUAGE: {lang}\n"
            f"The final_report field MUST be written entirely in {lang}. "
            "All section headings, findings, interpretations, and recommendations "
            f"must be in {lang}. Do not mix languages.\n\n"
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
            # Convert to PDF
            pdf_path = ai_dir / "ai_report.pdf"
            _convert_md_to_pdf(report_path, pdf_path)
            if pdf_path.exists():
                log.info("[AI] PDF report saved  → %s", pdf_path)

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
