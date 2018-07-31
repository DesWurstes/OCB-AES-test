cd "$(dirname "$0")"
rm -f test
gcc-8 main.c ocb-new/ocb.c ocb-reference/ocb.c ocb-reference/rijndael-alg-fst.c -o test -Ofast -march=native -mrdrnd
./test
