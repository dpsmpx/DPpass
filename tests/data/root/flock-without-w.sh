# Совместимый поднабор flock старого Android toybox; захват настоящий.
flock() {
    test "$#" = 3 && test "$1" = -x && test "$2" = -n && command flock "$@"
}
