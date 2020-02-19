

#SCHEMES="R5ND_1CCA_0d R5ND_1CCA_5d"
CPASCHEMES="R5ND_1CPA_0d R5ND_3CPA_0d R5ND_5CPA_0d R5ND_1CPA_5d R5ND_3CPA_5d R5ND_5CPA_5d R5N1_1CPA_0d R5N1_3CPA_0d R5N1_5CPA_0d R5ND_0CPA_2iot R5ND_1CPA_4longkey"
CCASCHEMES="R5ND_1CCA_0d R5ND_3CCA_0d R5ND_5CCA_0d R5ND_1CCA_5d R5ND_3CCA_5d R5ND_5CCA_5d R5N1_1CCA_0d R5N1_3CCA_0d R5N1_5CCA_0d R5N1_3CCA_0smallCT"
SCHEMES="$CPASCHEMES $CCASCHEMES"

TAUS="0 1 2"

KATDIR=.KATSHASUM

# move to parent dir
currentdir=$(pwd)
parentdir="$(dirname "$(pwd)")"
cd $parentdir

make clean
make NIST_KAT_GENERATION=1
for scheme in $SCHEMES
do
    for tauconf in $TAUS
    do
        ./reference/build/sample_kem -a $scheme -t $tauconf | tail -n 2 | shasum > shasum_$scheme$tauconf.sha
        mv shasum_$scheme$tauconf.sha $currentdir/$KATDIR/shasum_$scheme$tauconf.sha
    done
done


