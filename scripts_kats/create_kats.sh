
CPASCHEMES="R5ND_1CPA_0d R5ND_3CPA_0d R5ND_5CPA_0d R5ND_1CPA_5d R5ND_3CPA_5d R5ND_5CPA_5d R5N1_1CPA_0d R5N1_3CPA_0d R5N1_5CPA_0d R5ND_0CPA_2iot R5ND_1CPA_4longkey"
CCASCHEMES="R5ND_1CCA_0d R5ND_3CCA_0d R5ND_5CCA_0d R5ND_1CCA_5d R5ND_3CCA_5d R5ND_5CCA_5d R5N1_1CCA_0d R5N1_3CCA_0d R5N1_5CCA_0d R5N1_3CCA_0smallCT"
SCHEMES="$CPASCHEMES $CCASCHEMES"

KATDIRKEM=.KATSHASUM/NIST/KEM
KATDIRPKE=.KATSHASUM/NIST/PKE

mkdir .KATSHASUM/NIST
mkdir $KATDIRKEM
mkdir $KATDIRPKE


# move to parent dir
currentdir=$(pwd)
parentdir="$(dirname "$(pwd)")"
cd $parentdir

for scheme in $SCHEMES
do
    make clean
    make NIST_KAT_GENERATION=1 ALG=$scheme
    ./optimized/build/PQCgenKAT_kem
    sleep 2
    shasum PQCkemKAT_*.rsp > shasum_$scheme.sha
    mv shasum_$scheme.sha $currentdir/$KATDIRKEM/shasum_$scheme.sha
    mkdir $currentdir/$KATDIRKEM/$scheme
    mv PQCkemKAT_* $currentdir/$KATDIRKEM/$scheme/
done

for scheme in $CCASCHEMES
do
    make clean
    make NIST_KAT_GENERATION=1 ALG=$scheme
    ./optimized/build/PQCgenKAT_encrypt
    shasum PQCencryptKAT_*.rsp > shasum_$scheme.sha
    mv shasum_$scheme.sha $currentdir/$KATDIRPKE/shasum_$scheme.sha
    mkdir $currentdir/$KATDIRPKE/$scheme
    mv PQCencryptKAT_* $currentdir/$KATDIRPKE/$scheme/
done
