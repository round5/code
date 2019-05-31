################################################################################
#
# Perl module for parameter set handling.
#
################################################################################

package ParameterSets;

use strict;
use warnings;
use Exporter;
use Carp;

our @ISA = qw(Exporter);
our @EXPORT = qw(%apiLocations @paramSets %allParameters gatherConfigurations getParamSet getAlgNameFromParamSet variantNamePlain variantNameLaTeX getTau getProtocol getNistProtocol);
our @EXPORT_OK = @EXPORT;

# Locations of the algorithm parameters in the parameter set
our %apiLocations;

# All parameter sets (full string from the r5_parameter_sets.c file)
our @paramSets;

# The parameters (array) for each algorithm variant
our %allParameters;

# Read and interpret r5_parameter_sets.h and r5_parameter_sets.c to gather all configs
sub gatherConfigurations {
    my $paramFileName = "reference/src/r5_parameter_sets.h";
    open(my $paramFile, '<', $paramFileName) or confess "Unable to open $paramFileName";
    $apiLocations{NIST_LEVEL} = -2;
    $apiLocations{ALG_NAME} = -1;
    while (<$paramFile>) {
        $apiLocations{$1} = $2 if (/^#define\s+((?:API|POS)_\w+)\s+(\d+)/);
    }
    close($paramFile) or confess "Unable to close $paramFileName";
    my $nrSets = 0;
    $paramFileName = "reference/src/r5_parameter_sets.c";
    open($paramFile, '<', $paramFileName) or confess "Unable to open $paramFileName";
    while (<$paramFile>) {
        if (/^\s+{\s*(.*?)\s*},? \/\*\s*(\S*)\s*\*\//) {
            my $paramSet = "$1, " . substr($2,5,1) . ", $2"; # Add name and level
            push @paramSets, $paramSet;
            my @paramSet = getParamSet($nrSets++);
            my $isNonRing = $paramSet[$apiLocations{POS_N}] == 1;
            $allParameters{getAlgNameFromParamSet(@paramSet)} = \@paramSet;
        }
    }
    close($paramFile) or confess "Unable to close $paramFileName";
}

# Return the parameter for the given api set number set as separete items
sub getParamSet {
    my $apiSet = shift;
    my $paramSet = $paramSets[$apiSet];
    return () if !$paramSet;

    $paramSet =~ s/^\s+|\s+$//g;
    my @paramSet = split(/\s*,\s*/, $paramSet);

    return @paramSet;
}

# Return the algorithm name from the given A generation variant and parameter set
sub getAlgNameFromParamSet {
    my @paramSet = @_;
    return "" if !@paramSet;

    return $paramSet[$apiLocations{ALG_NAME}];
}

# Get descriptive name for variant (plain text)
sub variantNamePlain {
    my $variant = shift;
    confess "Can not determine LaTeX variant description from $variant" unless $variant =~ /R5(N1|ND)_(.)(PKE|KEM)_(.)([^ ]*)( T[012*])?( AES)?/;
    my ($type, $level, $protocol, $f, $suffix, $tau, $aes) = ($1, $2, $3, $4, $5, $6, $7);

    $level = '{1,3,5}' if ($level eq '*');

    $tau = ($type eq 'N1' and defined $tau and $tau =~ /(T[012])/) ? " $1" : "";
    $aes = defined $aes ? " (AES)" : "";

    return "R5${type}_${level}${protocol}_${f}$suffix$tau$aes";
}

# Get descriptive name for variant (LaTeX code)
sub variantNameLaTeX {
    my $latex = variantNamePlain(@_) =~ s/([_{}])/\\$1/gr;
    $latex =~ s/T([012])/\$\\tau=$1\$/;
    $latex =~ s/([}_])/$1\\allowbreak{}/g;
    return $latex;
}

# Gets the variant for generating A (tau) from a variant
sub getTau {
    my $variant = shift;
    if ($variant =~ / T(.)/) {
        return $1;
    } else {
        return 0;
    }
}

# Gets the protocol from a variant
sub getProtocol {
    my $variant = shift;
    confess "Unable to determine protocol from $variant" unless $variant =~ /(PKE|KEM)/;
    return $1;
}

# Gets the NIST protocol from a variant
sub getNistProtocol {
    return getProtocol(shift) eq "KEM" ? "kem" : "encrypt";
}

1;
