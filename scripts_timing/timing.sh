

CPASCHEMES="R5ND_1CPA_0d R5ND_3CPA_0d R5ND_5CPA_0d R5ND_1CPA_5d R5ND_3CPA_5d R5ND_5CPA_5d R5N1_1CPA_0d R5N1_3CPA_0d R5N1_5CPA_0d R5ND_0CPA_2iot R5ND_1CPA_4longkey"
CCASCHEMES="R5ND_1CCA_0d R5ND_3CCA_0d R5ND_5CCA_0d R5ND_1CCA_5d R5ND_3CCA_5d R5ND_5CCA_5d R5N1_1CCA_0d R5N1_3CCA_0d R5N1_5CCA_0d R5N1_3CCA_0smallCT"

SCHEMES="$CPASCHEMES $CCASCHEMES"

IMPLEMENTATIONS="optimized"
CTCONFIGURATIONS="None CM_CACHE CM_CT"
AVXCONFIGURATIONS="None AVX2"

AESCONFIGURATIONS="None" # "None AES"
SHAKELIBRARY="None STANDALONE"
TAUCONFIGURATIONS="0 1 2"

# where to store results
TIMINGRESULTS=timing_results_tuplehash100000.txt
#rm $TIMINGRESULTS

# move to parent dir
currentdir="$(pwd)"
parentdir="$(dirname "$(pwd)")"
cd $parentdir

#number executions
REP="100000"

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

                        GOON=true

                        # skip if external library and AVX2 since it is not supported
                        if [ $shakelib == "None" ]; then
                            if [ $avxconf == "AVX2" ]; then
                                GOON=false
                            fi
                        fi
                        # skip if ring and tau!=0
                        type="${scheme:0:4}"
                        if [ $type == "R5ND" ]; then
                            if [ $tauconf != "0" ]; then
                                GOON=false
                            fi
                        fi
                        # skip for non-ring variants not equal to 5CCA and with tau != 0
                        type="${scheme:0:4}"
                        if [ $type == "R5N1" ]; then
                            variant="${scheme:5:4}"
                            if [ $variant != "5CCA" ]; then
                                if [ $tauconf != "0" ]; then
                                    GOON=false
                                fi
                            fi
                        fi

                        if [ "$GOON" != false ]; then
                            #########
                            make clean
                            echo "NIST_KAT_GENERATION=1 ALG=$scheme $ctconf=1 $aesconf=1 TAU=$tauconf $avxconf=1 $shakelib=1 TIMING=$REP "
                            # places output of last kat in .debug_kats.txt
                            make -s NIST_KAT_GENERATION=1 ALG=$scheme $ctconf=1 $aesconf=1 TAU=$tauconf $avxconf=1 $shakelib=1 TIMING=$REP
                            for implementation in $IMPLEMENTATIONS
                            do
                            $(echo "NIST_KAT_GENERATION=1 ALG=$scheme $ctconf=1 $aesconf=1 TAU=$tauconf $avxconf=1 $shakelib=1 TIMING=$REP " >> $currentdir/$TIMINGRESULTS)
                            $(./optimized/build/sample_kem | tail -12 >> $currentdir/$TIMINGRESULTS)
                            $(echo "  " >> $currentdir/$TIMINGRESULTS)
                            done
                            #########
                        fi
                    done
                done
            done
        done
    done
done





