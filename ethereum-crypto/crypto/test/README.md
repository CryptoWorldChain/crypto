cp ../libethereum-crypto.so .
gcc test.c -L . -l crypto -I .. -o test
./test
