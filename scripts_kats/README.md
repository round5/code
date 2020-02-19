This folder contains several scripts to create and verify the outputs of the different implementations:

* File `create_simple_kats.sh` creates simple checks for all configurations.
* File `create_kats.sh` creates NIST KATs for all configurations.
* File `check_kat_simple.sh` checks the simple kats.
* File `check_kats.sh` checks NIST KATs.

Furthermore:

* Folder `.KATSHASUM` contains the fingerprints of the KATs. Rerunning the `create...` scripts overwrites the data. 
* Folder `.apifilesrefcon` contains api files required for the `reference` and `configurable` implementations.
