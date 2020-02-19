
CPASCHEMES="R5ND_1CPA_0d R5ND_3CPA_0d R5ND_5CPA_0d R5ND_1CPA_5d R5ND_3CPA_5d R5ND_5CPA_5d R5N1_1CPA_0d R5N1_3CPA_0d R5N1_5CPA_0d  R5ND_0CPA_2iot R5ND_1CPA_4longkey"
CCASCHEMES="R5ND_1CCA_0d R5ND_3CCA_0d R5ND_5CCA_0d R5ND_1CCA_5d R5ND_3CCA_5d R5ND_5CCA_5d R5N1_1CCA_0d R5N1_3CCA_0d R5N1_5CCA_0d R5N1_3CCA_0smallCT"
SCHEMES="$CPASCHEMES $CCASCHEMES "


IMPLEMENTATIONS="optimized reference configurable"

CTCONFIGURATIONS="CM_CT AVX2 None CM_CACHE"
FIPS202LIBRARY="STANDALONE None"

SUCCESS=true


# move to parent dir
currentdir=$(pwd)
parentdir="$(dirname "$(pwd)")"
cd $parentdir

echo $currentdir

KATDIR=.KATSHASUM
TMPDIR=.tmp
APIFOLDER=.apifilesrefcon

KATRESULTS=kat_results.txt
rm $KATRESULTS

rm -r $currentdir/$TMPDIR/*

for scheme in $SCHEMES
do
    for fips in $FIPS202LIBRARY
    do
        for ctconf in $CTCONFIGURATIONS
        do
            for implementation in $IMPLEMENTATIONS
            do
                cp -r $parentdir/reference $currentdir/$TMPDIR
		        cp -r $parentdir/configurable $currentdir/$TMPDIR
		        cp -r $parentdir/optimized $currentdir/$TMPDIR

                tau=0
                type="${scheme:0:4}"
                if [ $type == "R5N1" ]; then
                    tau=2
                fi

                # only needed for reference and configurable
                if [ $implementation != "optimized" ]; then
                    # if cca, make cca kem default
                    type="${scheme:6:3}"
                    if [ $type == "CCA" ]; then
                        cp $currentdir/$APIFOLDER/kem_cca.c $currentdir/$TMPDIR/$implementation/src/kem.c
                        cp $currentdir/$APIFOLDER/kem_cca.h $currentdir/$TMPDIR/$implementation/src/kem.h

                    fi
                    cp $currentdir/$APIFOLDER/PQCgenKAT_kem.c  $currentdir/$TMPDIR/$implementation/src/examples/PQCgenKAT_kem.c
                    cp $currentdir/$APIFOLDER/api_KEM_$scheme* $currentdir/$TMPDIR/$implementation/src/api.h
                fi

                cd $currentdir/$TMPDIR/$implementation

                make clean
                echo "ALG=$scheme $ctconf=1 $fips=1 TAU=$tau NIST_KAT_GENERATION=1 Implementation=$implementation"
                # places output of last kat in .debug_kats.txt
                make ALG=$scheme $ctconf=1 $fips=1 TAU=$tau NIST_KAT_GENERATION=1  > $currentdir/.debug_kats.txt

                ./build/PQCgenKAT_kem

                result=$(shasum PQCkemKAT*.rsp | shasum -c $currentdir/$KATDIR/NIST/KEM/shasum_$scheme.sha | grep "OK")
                # test whether the output string has lenght 0
                if [ -z "$result" ]; then
                    echo "KAT KEM($scheme, $implementation, TAU=$tau, $fips, $ctconf) FAILED"
                    echo "KAT KEM($scheme, $implementation, TAU=$tau, $fips, $ctconf) FAILED" >> $currentdir/$KATRESULTS
                    SUCCESS=false
                    break
                else
                    echo "KAT KEM($scheme, $implementation, TAU=$tau, $fips, $ctconf) OK!"
                    echo "KAT KEM($scheme, $implementation, TAU=$tau, $fips, $ctconf) OK!" >> $currentdir/$KATRESULTS
                fi

                if [ "$SUCCESS" == false ]; then
                    break
                fi

                if [ $implementation != "optimized" ]; then
                    rm /src/api.h
                fi

                rm -r $currentdir/$TMPDIR/*

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
    echo "KAT for all KEM schemes OK!"
    echo "KAT for all KEM schemes OK!" >> $currentdir/$KATRESULTS
fi

IMPLEMENTATIONS="optimized"

for scheme in $CCASCHEMES
do
    for fips in $FIPS202LIBRARY
    do
        for ctconf in $CTCONFIGURATIONS
        do
            for implementation in $IMPLEMENTATIONS
            do

                cp -r $parentdir/reference $currentdir/$TMPDIR
                cp -r $parentdir/configurable $currentdir/$TMPDIR
                cp -r $parentdir/optimized $currentdir/$TMPDIR

                tau=0
                type="${scheme:0:4}"
                if [ $type == "R5N1" ]; then
                    tau=2
                fi

                # only needed for reference and configurable
                if [ $implementation != "optimized" ]; then
                    # if cca, make cca kem default

                    cp $currentdir/$APIFOLDER/pke_cca.c $currentdir/$TMPDIR/$implementation/src/pke.c
                    cp $currentdir/$APIFOLDER/pke_cca.h $currentdir/$TMPDIR/$implementation/src/pke.h

                    cp $currentdir/$APIFOLDER/PQCgenKAT_encrypt.c  $currentdir/$TMPDIR/$implementation/src/examples/PQCgenKAT_encrypt.c
                    cp $currentdir/$APIFOLDER/api_PKE_$scheme* $currentdir/$TMPDIR/$implementation/src/api.h
                fi

                cd $currentdir/$TMPDIR/$implementation


                make clean

                echo "ALG=$scheme $ctconf=1 $fips=1 TAU=$tau Implementation=$implementation NIST_KAT_GENERATION=1"
                # places output of last kat in .debug_kats.txt
                make ALG=$scheme $ctconf=1 $fips=1 TAU=$tau NIST_KAT_GENERATION=1 > $currentdir/.debug_kats.txt

                ./build/PQCgenKAT_encrypt
                result=$(shasum PQCencryptKAT*.rsp | shasum -c $currentdir/$KATDIR/NIST/PKE/shasum_$scheme.sha | grep "OK")
                # test whether the output string has lenght 0
                if [ -z "$result" ]; then
                    echo "KAT PKE($scheme, $implementation, Tau=$tau, $fips, $ctconf) FAILED"
                    echo "KAT PKE($scheme, $implementation, Tau=$tau, $fips, $ctconf) FAILED" >> $currentdir/$KATRESULTS
                    SUCCESS=false
                    break
                else
                    echo "KAT PKE($scheme, $implementation, Tau=$tau, $fips, $ctconf) OK!"
                    echo "KAT PKE($scheme, $implementation, Tau=$tau, $fips, $ctconf) OK!" >> $currentdir/$KATRESULTS
                fi

                if [ "$SUCCESS" == false ]; then
                    break
                fi

                if [ $implementation != "optimized" ]; then
                    rm /src/api.h
                fi


                rm -r $currentdir/$TMPDIR/*

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
    echo "KAT for all PKE schemes OK!"
    echo "KAT for all PKE schemes OK!" >> $currentdir/$KATRESULTS
fi

#if everything went fine, remove debug file
rm $currentdir/.debug.txt


