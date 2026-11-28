#!/usr/bin/env python3
import contextlib
import io
from pathlib import Path
import tempfile
import unittest

import summarize_server_auto as summary


def event(stamp="2026-11-28T07:56:20.123Z", **changes):
    fields = {
        "context": "WIFI_TCP",
        "model_scored": "false",
        "observations_before": "null",
        "candidates": "2",
        "planned_moved": "0",
        "attempted": "1",
        "attempted_moved": "0",
        "verified_successes": "1",
        "measured_failures": "0",
        "unmeasured": "0",
        "first_attempt": "VERIFIED_SUCCESS",
        "first_moved": "false",
    }
    fields.update(changes)
    return f"{stamp} INFO core server_auto_outcome " + " ".join(f"{key}={value}" for key, value in fields.items())


FAILURE = {"verified_successes": 0, "measured_failures": 1, "first_attempt": "MEASURED_FAILURE"}
UNMEASURED = {"verified_successes": 0, "unmeasured": 1, "first_attempt": "NONE"}
SCORED = {"model_scored": "true", "observations_before": 8}
MOVED = {"planned_moved": 2, "attempted_moved": 1, "first_moved": "true"}
CLIP = "… пропущено 96000 символов середины журнала (всего 215400) …"


class SummarizeServerAutoTest(unittest.TestCase):
    def test_rates_use_measured_first_attempts_only_and_keep_contexts_separate(self):
        text = "\n".join((
            event(), event(**FAILURE), event(**UNMEASURED),
            event(**SCORED, **MOVED), event(**SCORED), event(**SCORED, **MOVED, **UNMEASURED),
            event(**SCORED, context="WIFI_QUIC", first_attempt="null", attempted=0, verified_successes=0),
        ))
        observations, notes = summary.parse_log(text)
        self.assertEqual(notes, [])
        totals = summary.summarize(observations)
        view = summary.render(totals)
        self.assertIn("| WIFI_TCP | 1/2 (50.0%) | 2/2 (100.0%) | +50.0 | 1 / 1 | 1/1 (100.0%) и 1 | 2/4 |", view)
        self.assertIn("| WIFI_QUIC | 0/0 (—) | 0/0 (—) | — | 0 / 0 |", view)
        self.assertNotIn("MOBILE_TCP", view)

    def test_coverage_tracks_all_candidates_and_outcomes_not_only_first(self):
        text = "\n".join((
            event(candidates=4, attempted=3, verified_successes=1, measured_failures=1, unmeasured=1),
            event(**SCORED, **MOVED, **FAILURE),
            event(**SCORED, **UNMEASURED),
            event(**SCORED, context="WIFI_QUIC", first_attempt="null", attempted=0, verified_successes=0),
        ))
        observations, _ = summary.parse_log(text)
        totals = summary.summarize(observations)
        view = summary.render_coverage(totals)
        self.assertIn("| WIFI_TCP | Штатный | 1 | 3/4 (75.0%) | 2/3 (66.7%) | 1/2 (50.0%) | 1 | 1/1 (100.0%) | 1/1 (100.0%) |", view)
        self.assertIn("| WIFI_TCP | V4 | 2 | 2/4 (50.0%) | 1/2 (50.0%) | 0/1 (0.0%) | 1 | 1/2 (50.0%) | 0/0 (—) |", view)
        self.assertIn("| WIFI_QUIC | V4 | 1 | 0/2 (0.0%) | 0/0 (—) | 0/0 (—) | 0 | 0/0 (—) | 0/0 (—) |", view)
        self.assertNotIn("MOBILE_TCP", view)
        self.assertIn("не доказывают преимущество модели", view)
        self.assertEqual(totals[("WIFI_TCP", True)].moved_first.failures, 1)

    def test_missing_comparison_cohort_is_explicit(self):
        with tempfile.TemporaryDirectory() as directory:
            planner = Path(directory) / "planner.txt"
            scored = Path(directory) / "scored.txt"
            planner.write_text(event(), encoding="utf-8")
            scored.write_text(event(), encoding="utf-8")
            status, stream, errors = self.invoke(str(planner), "--scored-log", str(scored))
            self.assertEqual((status, errors), (0, ""))
            self.assertIn("во втором экспорте нет событий с оценкой V4", stream)
            planner.write_text(event(**SCORED), encoding="utf-8")
            scored.write_text(event(**SCORED), encoding="utf-8")
            status, stream, errors = self.invoke(str(planner), "--scored-log", str(scored))
            self.assertEqual((status, errors), (0, ""))
            self.assertIn("в первом экспорте нет событий штатного плана", stream)

    def test_export_uses_current_tail_and_keeps_identical_events_inside_it(self):
        text = "\n".join((
            summary.EXPORT_TITLE,
            "=== Прошлый сеанс (хвост) ===",
            event() + " unrelated=old",
            summary.CURRENT_SESSION,
            event(**FAILURE),
            summary.ROTATION_BOUNDARY,
            event(**FAILURE),
            CLIP,
            "2026-11-28T07:56:20Z WARNING log queue_overflow lost=2",
            event(), event(),
            "2026-11-28T07:56:20Z INFO core unrelated message=server_auto_outcome",
        ))
        observations, notes = summary.parse_log(text)
        self.assertEqual([row.first for row in observations], ["VERIFIED_SUCCESS", "VERIFIED_SUCCESS"])
        self.assertEqual(len(notes), 2)

    def test_clipped_export_can_omit_the_current_session_header(self):
        text = "\n".join((summary.EXPORT_TITLE, "=== Прошлый сеанс (хвост) ===", event(**FAILURE), CLIP, event()))
        observations, notes = summary.parse_log(text)
        self.assertEqual([row.first for row in observations], ["VERIFIED_SUCCESS"])
        self.assertEqual(len(notes), 1)
        with self.assertRaises(ValueError):
            summary.parse_log(summary.EXPORT_TITLE + "\n" + event())

    def test_memory_export_and_numeric_diagnostic_report(self):
        text = "\n".join((summary.EXPORT_TITLE, summary.CURRENT_SESSION, summary.MEMORY_NOTE, event()))
        observations, notes = summary.parse_log(text)
        self.assertEqual(len(observations), 1)
        self.assertEqual(len(notes), 1)
        report = "\n".join((summary.REPORT_TITLE, "## Diagnostics", event(**FAILURE), "## Log", event("1785300000123")))
        observations, notes = summary.parse_log(report)
        self.assertEqual([row.first for row in observations], ["VERIFIED_SUCCESS"])
        self.assertEqual(len(notes), 1)

    def test_strict_export_can_redact_only_the_preexisting_observation_count(self):
        scored = event(model_scored="true", observations_before=1000)
        censored = scored.replace("observations_before=1000", "<redacted>")
        self.assertEqual(summary.parse_log(censored), summary.parse_log(scored))
        for text in (
            event().replace("observations_before=null", "<redacted>"),
            scored.replace("attempted=1", "<redacted>"),
            censored + " <redacted>",
            censored.replace(" <redacted>", ""),
        ):
            with self.subTest(text=text), self.assertRaises(ValueError):
                summary.parse_log(text)

    def test_rejects_malformed_or_inconsistent_events(self):
        for text in (
            event(context="TUNNEL_TCP"),
            event(attempted=-1),
            event(candidates=0),
            event(attempted=3, verified_successes=3),
            event(verified_successes=0),
            event(first_attempt="MEASURED_FAILURE"),
            event(model_scored="maybe"),
            event(**SCORED, planned_moved=1),
            event(**SCORED, planned_moved=2),
            event(**SCORED, **MOVED, first_attempt="null"),
            event(**SCORED, planned_moved=2, attempted_moved=1),
            event(**MOVED),
            event(model_scored="true", observations_before=1_000_000_001),
            event() + " context=MOBILE_TCP",
            event().replace(" unmeasured=0", ""),
            event().replace(" INFO ", " WARNING "),
            event("bad-time"),
        ):
            with self.subTest(text=text), self.assertRaisesRegex(ValueError, "строка 2"):
                summary.parse_log("\n" + text)

    def test_ambiguous_sessions_are_rejected(self):
        with self.assertRaises(ValueError):
            summary.parse_log("\n".join((summary.CURRENT_SESSION, event(), summary.CURRENT_SESSION, event())))
        start = "2026-11-28T07:56:20Z INFO app session_start version=0.8.3-rc.7-dev"
        with self.assertRaises(ValueError):
            summary.parse_log("\n".join((start, event(), start, event())))

    def test_cli_selects_only_requested_cohorts_from_separate_exports(self):
        with tempfile.TemporaryDirectory() as directory:
            planner = Path(directory) / "planner.txt"
            scored = Path(directory) / "scored.txt"
            planner.write_text("\r\n".join((event(**FAILURE), event(**SCORED, **MOVED))), encoding="utf-8-sig")
            scored.write_text("\n".join((event(), event(**SCORED, **MOVED))), encoding="utf-8")
            status, stream, errors = self.invoke(str(planner), "--scored-log", str(scored))
            self.assertEqual(status, 0)
            self.assertIn("| WIFI_TCP | 0/1 (0.0%) | 1/1 (100.0%) | +100.0 |", stream)
            self.assertEqual(errors, "")

    def test_cli_keeps_export_limits_with_the_saved_table(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "log.txt"
            text = "\n".join((summary.EXPORT_TITLE, summary.CURRENT_SESSION, summary.ROTATION_BOUNDARY, event()))
            path.write_text(text, encoding="utf-8")
            status, stream, errors = self.invoke(str(path))
            self.assertEqual((status, errors), (0, ""))
            self.assertIn("| WIFI_TCP |", stream)
            self.assertIn("- выбран хвост после ротации или обрезки экспорта.", stream)

    def test_cli_distinguishes_empty_and_invalid_input_without_echoing_data(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "log.txt"
            path.write_text("other diagnostic data", encoding="utf-8")
            self.assertEqual(self.invoke(str(path))[:2], (1, ""))
            path.write_text(event() + " profile=do-not-echo", encoding="utf-8")
            status, stream, errors = self.invoke(str(path))
            self.assertEqual((status, stream), (2, ""))
            self.assertNotIn("do-not-echo", errors)
            path.write_bytes(b"x" * (summary.MAX_INPUT + 1))
            self.assertEqual(self.invoke(str(path))[0], 2)
            path.write_bytes(b"\xff")
            self.assertEqual(self.invoke(str(path))[0], 2)

    @staticmethod
    def invoke(*args):
        output = io.StringIO()
        errors = io.StringIO()
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(errors):
            status = summary.main(args)
        return status, output.getvalue(), errors.getvalue()


if __name__ == "__main__":
    unittest.main()
