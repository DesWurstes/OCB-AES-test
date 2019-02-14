## OCB-AES test

This tool compares [my compact OCB-AES implementation](https://github.com/DesWurstes/OCB-AES) with the reference
implementation.

### Known issues

This tool sometimes segfaults when `0 < associated_data_length < 16`. A test failure never happens.
