

CPASCHEMES="R5ND_1CPA_0d R5ND_3CPA_0d R5ND_5CPA_0d R5ND_1CPA_5d R5ND_3CPA_5d R5ND_5CPA_5d R5N1_1CPA_0d R5N1_3CPA_0d R5N1_5CPA_0d R5ND_0CPA_2iot R5ND_1CPA_4longkey"
#CPASCHEMES="R5N1_1CPA_0d R5N1_3CPA_0d R5N1_5CPA_0d R5ND_0CPA_2iot R5ND_1CPA_4longkey"
CCASCHEMES="R5ND_1CCA_0d R5ND_3CCA_0d R5ND_5CCA_0d R5ND_1CCA_5d R5ND_3CCA_5d R5ND_5CCA_5d R5N1_1CCA_0d R5N1_3CCA_0d R5N1_5CCA_0d R5N1_3CCA_0smallCT"

SCHEMES="$CPASCHEMES $CCASCHEMES"

IMPLEMENTATIONS="reference configurable optimized"
CTCONFIGURATIONS="None CM_CACHE CM_CT"
TAUS="0 1 2"
LIBRARY="None STANDALONE"

SUCCESS=true

# move to parent dir
currentdir=$(pwd)
parentdir="$(dirname "$(pwd)")"
cd $parentdir

KATDIR=KATSHASUM
KATRESULTS=simple_kat_results.txt
KATDEBUG=debug_simple_kat.txt

rm $currentdir/$KATRESULTS


for scheme in $SCHEMES
do
	for ctconf in $CTCONFIGURATIONS
	do
        for lib in $LIBRARY
        do
            for tauconf in $TAUS
            do
                make clean
                echo "ALG=$scheme $ctconf=1 $TAU=$tauconf $lib=1 NIST_KAT_GENERATION=1"
                make ALG=$scheme $ctconf=1 TAU=$tauconf $lib=1 NIST_KAT_GENERATION=1 > $currentdir/$KATDEBUG
                ./optimized/build/sample_kem
                for implementation in $IMPLEMENTATIONS
                do
                    result=$(./$implementation/build/sample_kem | tail -n 2 | shasum -c $currentdir/.$KATDIR/shasum_$scheme$tauconf.sha | grep "OK")
                    # test whether the output string has lenght 0
                    if [ -z "$result" ]; then
                        echo "KAT(Algorith=$scheme, Implementation=$implementation, Tau=$tauconf, Library=$lib, Mode=$ctconf) FAILED"
                        echo "KAT(Algorith=$scheme, Implementation=$implementation, Tau=$tauconf, Library=$lib, Mode=$ctconf) FAILED" >> $currentdir/$KATRESULTS
                        SUCCESS=false
                        break
                    else
                        echo "KAT(Algorith=$scheme, Implementation=$implementation, Tau=$tauconf, Library=$lib, Mode=$ctconf) OK!"
                        echo "KAT(Algorith=$scheme, Implementation=$implementation, Tau=$tauconf, Library=$lib, Mode=$ctconf) OK!" >> $currentdir/$KATRESULTS
                    fi
                    if [ "$SUCCESS" == false ]; then
                        break
                    fi
                done
                if [ "$SUCCESS" == false ]; then
                    break
                fi
            done
            if [ "$SUCCESS" == false ]; then
            break
            fi
        done
        if [ "$SUCCESS" == false ]; then
        break
        fi
	done
	if [ "$SUCCESS" == false ]; then
		break
	fi
done

if [ "$SUCCESS" == true ]; then
	echo "KAT for all schemes OK!"
fi

#if everything went fine, remove debug file
rm $currentdir/$KATDEBUG


