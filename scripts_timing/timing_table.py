import numpy as np

import re

parameterSetsCPA = ["R5ND_1CPA_5d", "R5ND_3CPA_5d", "R5ND_5CPA_5d",
                 "R5ND_1CPA_0d", "R5ND_3CPA_0d", "R5ND_5CPA_0d",
                 "R5N1_1CPA_0d", "R5N1_3CPA_0d", "R5N1_5CPA_0d"]

parameterSetsCCA = ["R5ND_1CCA_5d", "R5ND_3CCA_5d", "R5ND_5CCA_5d",
                    "R5ND_1CCA_0d", "R5ND_3CCA_0d", "R5ND_5CCA_0d",
                    "R5N1_1CCA_0d", "R5N1_3CCA_0d", "R5N1_5CCA_0d" ]

parameterSetsSpecial = ["R5ND_0CPA_2iot", "R5ND_1CPA_4longkey", "R5N1_3CCA_0smallCT"]


parameterSetsRing = [   "R5ND_1CPA_5d", "R5ND_3CPA_5d", "R5ND_5CPA_5d",
                        "R5ND_1CPA_0d", "R5ND_3CPA_0d", "R5ND_5CPA_0d",
                         "R5ND_1CCA_5d", "R5ND_3CCA_5d", "R5ND_5CCA_5d",
                         "R5ND_1CCA_0d", "R5ND_3CCA_0d", "R5ND_5CCA_0d",
                        "R5ND_0CPA_2iot", "R5ND_1CPA_4longkey"]

parameterSetsNonRing = ["R5N1_1CPA_0d", "R5N1_3CPA_0d", "R5N1_5CPA_0d",
                        "R5N1_1CCA_0d", "R5N1_3CCA_0d", "R5N1_5CCA_0d",
                        "R5N1_3CCA_0smallCT"]

algorithms = ["KeyGen", "Enc", "Dec", "Total"]

cm_types =  ["None", "CM_CACHE", "CM_CT"]


filename = "timing_results.txt"

e = r'(\d+\.\d{2})'
e2 = r'(\d+)'

np.set_printoptions(precision=4)


def find_value(param="R5ND_1CPA_5d", cm_type="None", alg="Total", avx="None", inputTau="-1", aes="None", skip=False):
    #    # extract values from file
    
    if skip == True:
        return " n/a "
    
    if inputTau == "-1":
        #default
        if param[3] == "D":
            Tau = "TAU=0"
        else:
            Tau = "TAU=2"
    else:
        Tau = "TAU=" + inputTau

    with open(filename, "r") as fp:
        line = fp.readline()
        cnt = 0
        while line:

            if re.search(param, line) and re.search(cm_type, line) and re.search(avx, line) and re.search(aes, line) and re.search(Tau, line):

                num = 12
                line = fp.readline()
                while (num > 0) and line:

                    ### return ms and CPU
#                    if re.search(alg, line) and re.search("ms", line):
#                        s = str(map(float, re.findall(e, line)))
#                        s = s[0:len(s)-1]
#                        line = fp.readline()
#                        if re.search(alg, line) and re.search("CPU", line):
#                            ss = str(map(int, re.findall(e2, line)))
#                            ss = ss[1:len(ss)]
#                            return s + "/" + ss
                    ### return ms
#                    if re.search(alg, line) and re.search("ms", line):
#                        return str(map(float, re.findall(e, line)))
                    ### return CPU
                    if re.search(alg, line) and re.search("CPU", line):
                        return str(map(int, re.findall(e2, line)))
                    num -= 1
                    line = fp.readline()
                    cnt +=1
        
            line = fp.readline()
            cnt +=1

    return " - "

def latex_name(input):
    s = ""
    for c in input:
        if c == "_":
            s += "\_"
        else:
            s += c
    return s

def create_latex_table():
    s = ""
    s += "\\begin{landscape}\n"
    s += "\\begin{table*}\n"
    
    s += "\\caption{Performance comparison of Round5 KEMs, r5\_cpa\_kem and r5\_cca\_kem, using different parameter sets and different type of countermeasures against timing attacks. The first three blocks of rows include the performance for IND-CPA secure, IND-CCA secure, and special parameter sets. The following block of rows include performance numbers when AVX2 optimizations are enabled in non-ring parameter sets. The last row block compares performance of R5N1\_1CPA\_0d parameter set for different TAU choices. Numbers are given in thousands of CPU cycles in a machine running at 2.6 GHz.  }\n"
    s += "\label{tab:timing_countermeasure_comparison}\n"
    s += "\\tiny\n"
    
    s += "\\begin{center} \n"
    s += "\\begin{tabular}{c|c|ccc|ccc|ccc|ccc} \n"
    
    s += "\\toprule\n"
    s += " \multirow{2}{*}{Parameter set} & \multirow{2}{*}{Flags} & \multicolumn{3}{c}{KeyGen} & \multicolumn{3}{c}{Enc} & \multicolumn{3}{c}{Dec} & \multicolumn{3}{c}{Total}\\\\ \n"
    s += "                                &                        & cacheless & cm\_cache & cm\_ct & cacheless & cm\_cache & cm\_ct &cacheless & cm\_cache & cm\_ct &cacheless & cm\_cache & cm\_ct \\\\ \n"

    # block of rows with CPA parameter sets
    s += " \\midrule\n"
    for paramSet in parameterSetsCPA:
        s += latex_name(paramSet)
        s += "&"
        for alg in algorithms:
            for cm_type in cm_types:
                s += "&"
                value = find_value(paramSet, cm_type, alg)
                s += value[1:len(value)-1]
        
        s += "\\\\\n"

    # block of rows with CCA parameter sets
    s += " \\midrule\n"
    for paramSet in parameterSetsCCA:
        s += latex_name(paramSet)
        s += "&"
        for alg in algorithms:
            for cm_type in cm_types:
                s += "&"
                value = find_value(paramSet, cm_type, alg)
                s += value[1:len(value)-1]
        
        s += "\\\\\n"

    # block of rows with special parameter sets
    s += " \\midrule\n"
    for paramSet in parameterSetsSpecial:
        s += latex_name(paramSet)
        s += "&"
        for alg in algorithms:
            for cm_type in cm_types:
                s += "&"
                value = find_value(paramSet, cm_type, alg)
                s += value[1:len(value)-1]
        s += "\\\\\n"

    s += "\\bottomrule\n"
    s += "\\end{tabular}\n"
    s += "\\end{center}\n"
    s += "\\end{table*}\n"
    s += "\\end{landscape}\n"
    print s


def create_latex_table_avx2():
    s = ""
    s += "\\begin{landscape}\n"
    s += "\\begin{table*}\n"
    
    s += "\\caption{Performance comparison of Round5 KEMs, r5\_cpa\_kem and r5\_cca\_kem, using different parameter sets and different type of countermeasures against timing attacks with AVX2 instructions. The first block of rows include performance numbers for ring parameter sets. The second block of rows shows performance numbers for non-ring parameter sets. last row block compares performance of R5N1\_1CPA\_0d parameter set for different TAU choices. Numbers are given in thousands of CPU cycles in a machine running at 2.6 GHz. }\n"
    s += "\label{tab:timing_countermeasure_comparison_avx2}\n"
    s += "\\tiny\n"
    
    s += "\\begin{center} \n"
    s += "\\begin{tabular}{c|c|ccc|ccc|ccc|ccc} \n"
    
    s += "\\toprule\n"
    s += " \multirow{2}{*}{Parameter set} & \multirow{2}{*}{Flags} & \multicolumn{3}{c}{KeyGen} & \multicolumn{3}{c}{Enc} & \multicolumn{3}{c}{Dec} & \multicolumn{3}{c}{Total}\\\\ \n"
    s += "                                &                        & cacheless & cm\_cache & cm\_ct & cacheless & cm\_cache & cm\_ct &cacheless & cm\_cache & cm\_ct &cacheless & cm\_cache & cm\_ct \\\\ \n"

    # block of rows comparing RING parameter sets with AVX2 flag
    s += " \\midrule\n"
    for paramSet in parameterSetsRing:
        s += latex_name(paramSet)
        s += "& AVX2 "
        for alg in algorithms:
            for cm_type in cm_types:
                s += "&"
                skip = True
                if cm_type == "CM_CACHE" or cm_type == "CM_CT":
                    skip = False
                value = find_value(paramSet, cm_type, alg, "AVX", "0", "None", skip)
                s += value[1:len(value)-1]
        s += "\\\\\n"
    

    # block of rows comparing non-ring parameter sets with AVX2 flag
    s += " \\midrule\n"
    for paramSet in parameterSetsNonRing:
        s += latex_name(paramSet)
        s += "& AVX2 "
        for alg in algorithms:
            for cm_type in cm_types:
                s += "&"
                skip = True
                if cm_type == "CM_CACHE" or cm_type == "CM_CT":
                    skip = False
                value = find_value(paramSet, cm_type, alg, "AVX", "2", "None", skip)
                s += value[1:len(value)-1]
        s += "\\\\\n"

    # block of rows comparing Tau=1 and Tau=0
    s += " \\midrule\n"
    for t in ["0", "1"]:
        for paramSet in ["R5N1_1CPA_0d"]:
            s += latex_name(paramSet)
            s += "& AVX2, TAU="
            s += t
            for alg in algorithms:
                for cm_type in cm_types:
                    s += "&"
                    skip = True
                    if cm_type == "CM_CACHE" or cm_type == "CM_CT":
                        skip = False
                    value = find_value(paramSet, cm_type, alg, "AVX", t, "None", skip)
                    s += value[1:len(value)-1]
        s += "\\\\\n"


    s += "\\bottomrule\n"
    s += "\\end{tabular}\n"
    s += "\\end{center}\n"
    s += "\\end{table*}\n"
    s += "\\end{landscape}\n"
    print s

create_latex_table()


create_latex_table_avx2()


