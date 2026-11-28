#!/usr/bin/env python3
"""Сводка измерений автовыбора серверов из локального журнала DPpass."""

import argparse
from dataclasses import dataclass, field
from pathlib import Path
import re
import sys


CONTEXTS = ("MOBILE_TCP", "MOBILE_QUIC", "WIFI_TCP", "WIFI_QUIC", "OTHER_TCP", "OTHER_QUIC")
FIRST_OUTCOMES = ("VERIFIED_SUCCESS", "MEASURED_FAILURE", "NONE", "null")
COUNTS = (
    "candidates", "attempted", "planned_moved", "attempted_moved",
    "verified_successes", "measured_failures", "unmeasured",
)
FIELDS = {"context", "model_scored", "observations_before", *COUNTS, "first_attempt", "first_moved"}
TIMESTAMP = re.compile(r"(?:[0-9]{1,19}|[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,9})?Z)")
CLIP_BOUNDARY = re.compile(r"… пропущено [0-9]+ символов середины журнала \(всего [0-9]+\) …")
ROTATION_BOUNDARY = "… (начало сеанса выше, дальше — последние части) …"
MEMORY_NOTE = "(журнал на телефоне выключен — события этого запуска из памяти)"
CURRENT_SESSION = "=== Текущий сеанс ==="
EXPORT_TITLE = "=== DPpass — журнал ==="
REPORT_TITLE = "# DPpass diagnostic report"
MAX_INPUT = 4 * 1024 * 1024


@dataclass(frozen=True)
class Observation:
    context: str
    scored: bool
    planned_moved: int
    attempted_moved: int
    first: str
    first_moved: bool
    candidates: int
    attempted: int
    successes: int
    failures: int
    unmeasured: int


@dataclass
class FirstAttempts:
    successes: int = 0
    failures: int = 0
    unmeasured: int = 0

    def add(self, outcome):
        if outcome == "VERIFIED_SUCCESS":
            self.successes += 1
        elif outcome == "MEASURED_FAILURE":
            self.failures += 1
        elif outcome == "NONE":
            self.unmeasured += 1

    @property
    def measured(self):
        return self.successes + self.failures

    @property
    def rate(self):
        return 100 * self.successes / self.measured if self.measured else None

    def render(self):
        rate = self.rate
        return f"{self.successes}/{self.measured} ({rate:.1f}%)" if rate is not None else "0/0 (—)"


@dataclass
class Cohort:
    first: FirstAttempts = field(default_factory=FirstAttempts)
    moved_first: FirstAttempts = field(default_factory=FirstAttempts)
    planned_moved: int = 0
    attempted_moved: int = 0
    plans: int = 0
    candidates: int = 0
    attempted: int = 0
    successes: int = 0
    failures: int = 0
    unmeasured: int = 0
    unchanged_first: FirstAttempts = field(default_factory=FirstAttempts)

    def add(self, observation):
        self.first.add(observation.first)
        self.plans += 1
        self.candidates += observation.candidates
        self.attempted += observation.attempted
        self.successes += observation.successes
        self.failures += observation.failures
        self.unmeasured += observation.unmeasured
        if observation.first_moved:
            self.moved_first.add(observation.first)
        else:
            self.unchanged_first.add(observation.first)
        self.planned_moved += observation.planned_moved
        self.attempted_moved += observation.attempted_moved


def count(value, maximum=2_147_483_647):
    if not re.fullmatch(r"0|[1-9][0-9]{0,9}", value) or int(value) > maximum:
        raise ValueError("недопустимый счётчик")
    return int(value)


def flag(value):
    if value not in ("true", "false"):
        raise ValueError("недопустимое логическое поле")
    return value == "true"


def parse_observation(parts):
    fields = {}
    omitted = 0
    for token in parts:
        if token == "<redacted>":
            omitted += 1
            continue
        key, sep, value = token.partition("=")
        if not sep or not value or key not in FIELDS or key in fields:
            raise ValueError("неизвестное, пустое или повторное поле")
        fields[key] = value
    # Строгий экспорт скрывает целую длинную пару observations_before=число.
    # Число накопленных наблюдений не участвует в сводке исходов попыток.
    missing = FIELDS - fields.keys()
    if (missing or omitted) and not (
        omitted == 1 and missing == {"observations_before"} and fields.get("model_scored") == "true"
    ):
        raise ValueError("неполный набор полей")

    context = fields["context"]
    first = fields["first_attempt"]
    if context not in CONTEXTS or first not in FIRST_OUTCOMES:
        raise ValueError("недопустимый контекст или исход")
    scored = flag(fields["model_scored"])
    first_moved = flag(fields["first_moved"])
    candidates, attempted, planned_moved, attempted_moved, successes, failures, unmeasured = (
        count(fields[key]) for key in COUNTS
    )
    observations = fields.get("observations_before")
    if scored:
        if observations is not None:
            count(observations, 1_000_000_000)
    elif observations != "null" or planned_moved:
        raise ValueError("несогласованные поля штатного плана")

    if (candidates == 0 or attempted > candidates or planned_moved > candidates or planned_moved % 2
            or attempted_moved > min(attempted, planned_moved)
            or planned_moved - attempted_moved > candidates - attempted
            or successes + failures + unmeasured != attempted):
        raise ValueError("несогласованные счётчики кандидатов")
    if first == "null":
        if first_moved:
            raise ValueError("отсутствует первая попытка")
    elif (not (attempted_moved if first_moved else attempted - attempted_moved)
          or (first == "VERIFIED_SUCCESS" and not successes)
          or (first == "MEASURED_FAILURE" and not failures)):
        raise ValueError("несогласованный исход первой попытки")

    return Observation(context, scored, planned_moved, attempted_moved, first, first_moved,
                       candidates, attempted, successes, failures, unmeasured)


def select_lines(text):
    """Выбрать одну сессию и отбросить дублирующееся начало экспорта."""
    lines = list(enumerate(text.splitlines(), 1))
    notes = []
    current = [index for index, (_, line) in enumerate(lines) if line == CURRENT_SESSION]
    titles = sum(line == EXPORT_TITLE for _, line in lines)
    if current or titles:
        if len(current) > 1 or titles > 1:
            raise ValueError("экспорт должен содержать один текущий сеанс")
        if current:
            start = current[0] + 1
            end = next((i for i in range(start, len(lines)) if lines[i][1].startswith("=== ")), len(lines))
            lines = lines[start:end]
        elif not any(CLIP_BOUNDARY.fullmatch(line) for _, line in lines):
            raise ValueError("в экспорте отсутствует текущий сеанс")
    elif lines and lines[0][1] == REPORT_TITLE:
        log_sections = [index for index, (_, line) in enumerate(lines) if line == "## Log"]
        if len(log_sections) > 1:
            raise ValueError("в отчёте несколько разделов журнала")
        lines = lines[log_sections[0] + 1:] if log_sections else []
        notes.append("диагностический отчёт содержит кольцо событий")

    start = 0
    for index, (_, line) in enumerate(lines):
        if line == ROTATION_BOUNDARY or CLIP_BOUNDARY.fullmatch(line):
            start = index + 1
    if start:
        notes.append("выбран хвост после ротации или обрезки экспорта")
    if any(line == MEMORY_NOTE for _, line in lines):
        notes.append("источник — кольцо событий в памяти")
    lines = lines[start:]
    starts = 0
    overflow = False
    for _, line in lines:
        event = line.split(maxsplit=4)[1:4]
        if event == ["INFO", "app", "session_start"]:
            starts += 1
        elif event == ["WARNING", "log", "queue_overflow"]:
            overflow = True
    if starts > 1:
        raise ValueError("в журнале несколько запусков приложения")
    if overflow:
        notes.append("в выбранном фрагменте отмечена потеря строк")
    return lines, notes


def parse_log(text):
    lines, notes = select_lines(text)
    observations = []
    for number, line in lines:
        prefix = line.split(maxsplit=4)
        if prefix[2:4] != ["core", "server_auto_outcome"]:
            continue
        try:
            if len(prefix) != 5 or prefix[1] != "INFO" or not TIMESTAMP.fullmatch(prefix[0]):
                raise ValueError("недопустимый заголовок события")
            observations.append(parse_observation(prefix[4].split()))
        except ValueError as error:
            raise ValueError(f"строка {number} · {error}") from None
    return observations, notes


def summarize(observations):
    totals = {}
    for observation in observations:
        key = (observation.context, observation.scored)
        if key not in totals:
            totals[key] = Cohort()
        totals[key].add(observation)
    return totals


def render(totals):
    rows = [
        "| Контекст | Штатный план, успехи/измерено | V4, успехи/измерено | Δ V4, п. п. | "
        "Первые без измерения, штатный / V4 | Перемещённый первый V4, успехи/измерено и без измерения | "
        "Перемещено V4, испробовано/в плане |",
        "|---|---:|---:|---:|---:|---:|---:|",
    ]
    for context in CONTEXTS:
        if (context, False) not in totals and (context, True) not in totals:
            continue
        planner = totals.get((context, False), Cohort())
        scored = totals.get((context, True), Cohort())
        before, after = planner.first.rate, scored.first.rate
        delta = f"{after - before:+.1f}" if before is not None and after is not None else "—"
        rows.append(
            f"| {context} | {planner.first.render()} | {scored.first.render()} | {delta} | "
            f"{planner.first.unmeasured} / {scored.first.unmeasured} | "
            f"{scored.moved_first.render()} и {scored.moved_first.unmeasured} | "
            f"{scored.attempted_moved}/{scored.planned_moved} |"
        )
    return "\n".join(rows)


def fraction(numerator, denominator):
    return f"{numerator}/{denominator} ({100 * numerator / denominator:.1f}%)" if denominator else "0/0 (—)"


def render_coverage(totals):
    rows = [
        "### Полнота измерений по контекстам",
        "",
        "| Контекст | Группа | Планов с кандидатами | Испробовано/допущено | "
        "Измерено/испробовано | Успехи/измерено | Без измерения | "
        "Первых измерено/зафиксировано | Первые без перестановки, успехи/измерено |",
        "|---|---|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for context in CONTEXTS:
        for scored in (False, True):
            cohort = totals.get((context, scored))
            if cohort is None:
                continue
            measured = cohort.successes + cohort.failures
            first_total = cohort.first.measured + cohort.first.unmeasured
            group = "V4" if scored else "Штатный"
            rows.append(
                f"| {context} | {group} | {cohort.plans} | "
                f"{fraction(cohort.attempted, cohort.candidates)} | "
                f"{fraction(measured, cohort.attempted)} | "
                f"{fraction(cohort.successes, measured)} | {cohort.unmeasured} | "
                f"{fraction(cohort.first.measured, first_total)} | {cohort.unchanged_first.render()} |"
            )
    rows.extend((
        "",
        "V4 означает наличие оценки модели, а не обязательную перестановку. "
        "Доли описывают наблюдения, не доказывают преимущество модели. "
        "Кандидаты повторно учитываются в разных планах; сравнивать следует "
        "сопоставимые серии в одной сети и с тем же набором кандидатов.",
    ))
    return "\n".join(rows)


def read_log(path):
    with path.open("rb") as stream:
        raw = stream.read(MAX_INPUT + 1)
    if len(raw) > MAX_INPUT:
        raise ValueError("журнал превышает 4 МиБ")
    return parse_log(raw.decode("utf-8-sig"))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("log", type=Path, help="экспорт журнала DPpass в UTF-8")
    parser.add_argument("--scored-log", type=Path, help="отдельный экспорт для событий с оценкой V4")
    args = parser.parse_args(argv)
    try:
        observations, notes = read_log(args.log)
        if args.scored_log is not None:
            scored, scored_notes = read_log(args.scored_log)
            observations = [row for row in observations if not row.scored] + [row for row in scored if row.scored]
            notes = [f"Штатный план · {note}" for note in notes] + [f"V4 · {note}" for note in scored_notes]
            if not any(not row.scored for row in observations):
                notes.append("в первом экспорте нет событий штатного плана")
            if not any(row.scored for row in observations):
                notes.append("во втором экспорте нет событий с оценкой V4")
    except (OSError, UnicodeError):
        print("Не удалось прочитать журнал в UTF-8.", file=sys.stderr)
        return 2
    except ValueError as error:
        print(f"Некорректный журнал · {error}", file=sys.stderr)
        return 2

    if not observations:
        for note in notes:
            print(note, file=sys.stderr)
        print("В выбранном фрагменте нет событий server_auto_outcome.", file=sys.stderr)
        return 1
    totals = summarize(observations)
    print(render(totals))
    print()
    print(render_coverage(totals))
    if notes:
        print()
        for note in notes:
            print(f"- {note}.")
    return 0


if __name__ == "__main__":
    sys.stdout.reconfigure(encoding="utf-8")
    sys.stderr.reconfigure(encoding="utf-8")
    sys.exit(main())
