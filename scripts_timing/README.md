To obtain timing results do the following:

1. Run `./timing.sh`. This will run the optimized code through all configurations and place the results in the file `timing_results.txt`.
2. Run `python timing_table.py` to obtain the table containing performance results as included in the Round5 specification.

Note that it is possible to obtain timing results of a specific Round5 configurations by running `make` with the compiler flag `TIMING=1`.
