#!/usr/bin/env bash
# run_tests.sh : compile (ASan + UBSan) et lance les tests des modules C.
#
#   ./run_tests.sh                    → tous les tests (nouveaux + existants), affichage résumé
#   ./run_tests.sh flow dchained_list → seulement ceux-là
#   ./run_tests.sh -v flow_table      → affichage complet (rapports ASan entiers)
#   ./run_tests.sh flow_table ft_add  → un 2e mot après le nom = filtre sur le titre des tests
#                                       (seulement pour les NOUVEAUX tests)
#
# NOUVEAUX tests (mini-framework test_common.h : un test = un process, plantage = test rouge) :
#     utils  portmap  dchained_list  rules  flow  flow_table  integration  capture  mmap_ring  ipset  engine
#       (capture = socket réel : lancer avec  sudo -E ./run_tests.sh capture   ·   CAP_IFACE=veth0 pour choisir ton interface)
#       (integration = conventions 0/-1/1, carte mémoire, et vrais octets de paquets de bout en bout)
# Tests EXISTANTS (tes propres fichiers, lancés tels quels) :
#     dict           → dict/test_dict.c
#     parser         → parser/test_parser.c
#     parser_hard    → parser/test_parser_hard.c
#     parser_claude  → parser/test_parser_claude.c
#
# Les logs complets sont dans build/tests/<nom>.log (et .compile.log pour la compilation).
# Pour déboguer un nouveau test dans gdb :  TC_NOFORK=1 gdb --args build/tests/flow_table "ft_add"

cd "$(dirname "$0")" || exit 1

CC="${CC:-gcc}"
FLAGS="-std=gnu11 -g -O0 -Wall -Wextra -pthread -fsanitize=address,undefined -fno-omit-frame-pointer"
OUT="build/tests"
mkdir -p "$OUT"

declare -A SRC KIND
# nouveaux
SRC[utils]="utils/test_utils.c utils/utils.c";                                   KIND[utils]=new
SRC[portmap]="portmap/test_portmap.c portmap/portmap.c";                         KIND[portmap]=new
SRC[dchained_list]="dchained_list/test_dchained_list.c dchained_list/dchained_list.c"; KIND[dchained_list]=new
SRC[flow]="utils/utils.c flows/test_flow.c flows/flow.c dict/dict.c";                          KIND[flow]=new
SRC[flow_table]="flows/test_flow_table.c flows/flow_table.c flows/flow.c dict/dict.c dchained_list/dchained_list.c portmap/portmap.c utils/utils.c rules/rules.c"; KIND[flow_table]=new
SRC[integration]="test_integration.c parser/parser.c flows/flow.c flows/flow_table.c dict/dict.c dchained_list/dchained_list.c portmap/portmap.c utils/utils.c rules/rules.c"; KIND[integration]=new
SRC[capture]="capture/test_capture.c capture/capture.c parser/parser.c flows/flow.c flows/flow_table.c dict/dict.c dchained_list/dchained_list.c portmap/portmap.c utils/utils.c rules/rules.c"; KIND[capture]=new
SRC[mmap_ring]="mmap_ring/test_mmap_ring.c mmap_ring/mmap_ring.c"; KIND[mmap_ring]=new
SRC[ipset]="ipset/test_ipset.c ipset/ipset.c utils/utils.c"; KIND[ipset]=new
SRC[ipset_m]="ipset_m/test_ipset_m.c ipset_m/ipset_m.c ipset/ipset.c dict/dict.c utils/utils.c"; KIND[ipset_m]=new
SRC[rules]="rules/test_rules.c rules/rules.c portmap/portmap.c"; KIND[rules]=new
SRC[engine]="engine/test_engine.c engine/engine.c capture/capture.c ipset/ipset.c mmap_ring/mmap_ring.c parser/parser.c flows/flow.c flows/flow_table.c dict/dict.c dchained_list/dchained_list.c portmap/portmap.c utils/utils.c rules/rules.c"; KIND[engine]=new
# existants
SRC[dict]="utils/utils.c dict/test_dict.c dict/dict.c";                                        KIND[dict]=old
SRC[parser]="parser/test_parser.c parser/parser.c";                              KIND[parser]=old
SRC[parser_hard]="parser/test_parser_hard.c parser/parser.c";                    KIND[parser_hard]=old
SRC[parser_claude]="parser/test_parser_claude.c parser/parser.c";                KIND[parser_claude]=old
ORDER=(utils portmap dchained_list rules flow flow_table integration capture mmap_ring ipset ipset_m engine dict parser parser_hard parser_claude)

VERBOSE=0
NAMES=()
FILTER=""
for arg in "$@"; do
    if [ "$arg" = "-v" ]; then VERBOSE=1
    elif [ -n "${SRC[$arg]:-}" ]; then NAMES+=("$arg")
    elif [ "${#NAMES[@]}" -gt 0 ]; then FILTER="$arg"
    else echo "Nom inconnu : $arg  (possibles : ${ORDER[*]})"; exit 2; fi
done
[ "${#NAMES[@]}" -eq 0 ] && NAMES=("${ORDER[@]}")

# résumé d'un log de test EXISTANT (leurs formats : « Total checks / PASS / FAIL » ou « N/M tests OK »)
resume_ancien() {
    local log="$1" total pass fail
    if grep -q "Total checks" "$log"; then
        total=$(grep -m1 "Total checks" "$log" | grep -oE '[0-9]+' | head -1)
        pass=$(grep -m1 -E "^ *PASS" "$log" | grep -oE '[0-9]+' | head -1)
        fail=$(grep -m1 -E "^ *FAIL" "$log" | grep -oE '[0-9]+' | head -1)
        echo "✓ ${pass:-?} OK   ✗ ${fail:-?} échecs   (sur ${total:-?} vérifications)"
    else
        grep -E "tests OK" "$log" | tail -1 | sed 's/^ *//'
    fi
}

# affichage court d'un log de test EXISTANT : les échecs, avec le titre de leur section
affiche_ancien() {
    awk '
        /^TEST :|^── /            { section = $0 }
        /\[FAIL\]|❌/              { if (section != "" && section != vue) { print "▶ " section; vue = section }
                                     print "      " $0; next }
        /Total checks|^ *PASS|^ *FAIL|tests OK/ { print "   " $0 }
        /ERROR: (Address|Leak)Sanitizer|runtime error|^SUMMARY:/ { print "   💥 " $0 }
    ' "$1"
}

declare -A RESULT
GLOBAL=0
for name in "${NAMES[@]}"; do
    bin="$OUT/$name"
    echo
    echo "════════ $name ($([ "${KIND[$name]}" = new ] && echo nouveaux tests || echo "tes tests existants")) ════════"
    LIBS=""; case "$name" in capture|engine) LIBS="-lpcap" ;; esac     # capture.c utilise libpcap (comme setup.py)
    if ! $CC $FLAGS ${SRC[$name]} -o "$bin" $LIBS 2> "$OUT/$name.compile.log"; then
        echo "✗✗ $name : la compilation a échoué"
        cat "$OUT/$name.compile.log"
        RESULT[$name]="ne compile pas"
        GLOBAL=1
        continue
    fi
    nwarn=$(grep -c "warning:" "$OUT/$name.compile.log")
    [ "$nwarn" -gt 0 ] && echo "(compilation : $nwarn avertissement(s), voir $OUT/$name.compile.log)"

    if [ "${KIND[$name]}" = new ]; then
        if [ "$VERBOSE" -eq 1 ]; then
            "$bin" $FILTER 2>&1 | tee "$OUT/$name.log"
            code=${PIPESTATUS[0]}
        else
            "$bin" $FILTER > "$OUT/$name.log" 2>&1
            code=$?
            grep -E '^(▶|   (✓|✗|💥|⏱)|      (✗|·)|─| ✓ )|ERROR: (Address|Leak)Sanitizer|runtime error|^(READ|WRITE) of size|SUMMARY:|^    #[0-3] ' "$OUT/$name.log"
        fi
        RESULT[$name]=$(grep -E '✓ [0-9]+ OK' "$OUT/$name.log" | tail -1 | sed 's/^ *//')
    else
        [ -n "$FILTER" ] && echo "(le filtre « $FILTER » ne s'applique pas aux tests existants : ignoré)"
        if [ "$VERBOSE" -eq 1 ]; then
            "$bin" 2>&1 | tee "$OUT/$name.log"
            code=${PIPESTATUS[0]}
        else
            "$bin" > "$OUT/$name.log" 2>&1
            code=$?
            affiche_ancien "$OUT/$name.log"
        fi
        RESULT[$name]=$(resume_ancien "$OUT/$name.log")
    fi
    [ "$code" -ne 0 ] && GLOBAL=1
done

echo
echo "════════════ RÉSUMÉ ════════════"
for name in "${NAMES[@]}"; do
    printf "  %-14s %s\n" "$name" "${RESULT[$name]:-?}"
done
[ "$VERBOSE" -eq 0 ] && echo "  (détail complet : $OUT/<nom>.log   ·   ./run_tests.sh -v <nom> pour tout voir)"
exit $GLOBAL
