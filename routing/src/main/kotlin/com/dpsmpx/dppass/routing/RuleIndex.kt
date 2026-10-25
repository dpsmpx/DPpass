package com.dpsmpx.dppass.routing

/**
 * Индекс правил по имени назначения (D-89): какие правила вообще могут
 * сработать на имя — номера по порядку правил.
 *
 * - Правило без доменов и geosite проверяется всегда: имя ему не условие.
 * - Правило, где все домены — точные ([DomainMatcher.Full]) или суффиксы
 *   ([DomainMatcher.Suffix]) и нет geosite, проверяется, только если имя
 *   запроса или его суффикс по границе метки есть в индексе. Без имени
 *   такое правило не срабатывает вовсе.
 * - Остальные (подстрока, geosite, необычный суффикс — пустой или с точкой
 *   впереди) проверяются всегда при наличии имени: индексом их не сузить.
 *
 * Кандидаты — надмножество сработавших правил, порядок прежний, поэтому
 * первое сработавшее правило то же, что у перебора всех.
 */
internal class RuleIndex(rules: List<Rule>) {
    /** Правила без условия на имя: кандидаты всегда. */
    private val withoutName: IntArray

    /** Правила с именем, которые индексом не сузить: кандидаты при любом имени. */
    private val unindexed: IntArray
    private val byFull: Map<String, IntArray>
    private val bySuffix: Map<String, IntArray>

    init {
        val without = ArrayList<Int>()
        val any = ArrayList<Int>()
        val full = HashMap<String, MutableList<Int>>()
        val suffix = HashMap<String, MutableList<Int>>()
        for ((i, rule) in rules.withIndex()) {
            val c = rule.conditions
            if (c.domains.isEmpty() && c.geoSites.isEmpty()) {
                without += i
                continue
            }
            if (c.geoSites.isNotEmpty() || c.domains.any { !indexable(it) }) {
                any += i
                continue
            }
            for (m in c.domains) {
                when (m) {
                    is DomainMatcher.Full -> full.getOrPut(m.name) { ArrayList() } += i
                    is DomainMatcher.Suffix -> suffix.getOrPut(m.suffix) { ArrayList() } += i
                    is DomainMatcher.Keyword -> Unit
                }
            }
        }
        withoutName = without.toIntArray()
        unindexed = (without + any).sorted().toIntArray()
        byFull = full.mapValues { (_, v) -> v.distinct().toIntArray() }
        bySuffix = suffix.mapValues { (_, v) -> v.distinct().toIntArray() }
    }

    /** Номера правил-кандидатов по возрастанию; без имени — только правила без условия на имя. */
    fun candidates(domain: String?): IntArray {
        if (domain == null) return withoutName
        val hits = ArrayList<IntArray>(2)
        byFull[domain]?.let(hits::add)
        // Сам домен и всё после каждой точки: суффикс совпадает только по границе метки.
        var from = 0
        while (true) {
            bySuffix[if (from == 0) domain else domain.substring(from)]?.let(hits::add)
            val dot = domain.indexOf('.', from)
            if (dot < 0) break
            from = dot + 1
        }
        if (hits.isEmpty()) return unindexed
        val out = java.util.TreeSet<Int>()
        unindexed.forEach(out::add)
        hits.forEach { a -> a.forEach(out::add) }
        return out.toIntArray()
    }

    private companion object {
        /** Суффикс индексируется, если он непустой и не начинается с точки: иначе сравнение по границе метки другое. */
        fun indexable(m: DomainMatcher): Boolean = when (m) {
            is DomainMatcher.Full -> true
            is DomainMatcher.Suffix -> m.suffix.isNotEmpty() && !m.suffix.startsWith('.')
            is DomainMatcher.Keyword -> false
        }
    }
}
