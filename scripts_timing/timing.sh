

CPASCHEMES="R5ND_1CPA_0d R5ND_3CPA_0d R5ND_5CPA_0d R5ND_1CPA_5d R5ND_3CPA_5d R5ND_5CPA_5d R5N1_1CPA_0d R5N1_3CPA_0d R5N1_5CPA_0d R5ND_0CPA_2iot R5ND_1CPA_4longkey"
CCASCHEMES="R5ND_1CCA_0d R5ND_3CCA_0d R5ND_5CCA_0d R5ND_1CCA_5d R5ND_3CCA_5d R5ND_5CCA_5d R5N1_1CCA_0d R5N1_3CCA_0d R5N1_5CCA_0d R5N1_3CCA_0smallCT"

SCHEMES="$CPASCHEMES $CCASCHEMES"

IMPLEMENTATIONS="optimized"
CTCONFIGURATIONS="None CM_CACHE CM_CT"
AVXCONFIGURATIONS="None AVX2"

AESCONFIGURATIONS="None AES"
SHAKELIBRARY="None STANDALONE"
TAUCONFIGURATIONS="0 1 2"

# where to store results
TIMINGRESULTS=timing_results.txt
rm $TIMINGRESULTS

# move to parent dir
currentdir="$(pwd)"
parentdir="$(dirname "$(pwd)")"
cd $parentdir

# go through configurations and get results
for scheme in $SCHEMES
do
    for ctconf in $CTCONFIGURATIONS
    do
        for avxconf in $AVXCONFIGURATIONS
        do
            for aesconf in $AESCONFIGURATIONS
            do
                for shakelib in $SHAKELIBRARY
                do
                    for tauconf in $TAUCONFIGURATIONS
                    do
                        #########
                        make clean
                        echo "ALG=$scheme $ctconf=1 $aesconf=1 TAU=$tauconf $avxconf=1 $shakelib=1 TIMING=1 "
                        # places output of last kat in .debug_kats.txt
                        make ALG=$scheme $ctconf=1 $aesconf=1 TAU=$tauconf $avxconf=1 $shakelib=1 TIMING=1
                        for implementation in $IMPLEMENTATIONS
                        do
                            $(echo "ALG=$scheme $ctconf=1 $aesconf=1 TAU=$tauconf $avxconf=1 $shakelib=1 TIMING=1 " >> $currentdir/$TIMINGRESULTS)
                            $(./optimized/build/sample_kem | tail -12 >> $currentdir/$TIMINGRESULTS)
                            $(echo "  " >> $currentdir/$TIMINGRESULTS)
                        done
                        #########
                    done
                done
            done
        done
    done
done





