## OCB-AES test

This tool compares [my compact OCB-AES implementation](https://github.com/DesWurstes/OCB-AES) with the reference
implementation.

### Known issues

This tool sometimes segfaults when `(associated_data_length %= 16) != 0`. A test failure never happens.
