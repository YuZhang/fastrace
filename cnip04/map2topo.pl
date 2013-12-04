#!/usr/bin/perl -W
use strict;

my $out_pfx=shift;
$out_pfx || die "Usage: programe out_pfx [in_file ... ]\n";

my %node;
my %edge;
while(<>) {
  chomp;
  my @t = split /\s+/, $_;
  #next if ($t[0] =~ /W/);
  #shift @t;
  if ($#t != 1 and $#t != 2) {
    warn "invalid line: $_\n";
    next;
  }
  $node{$t[0]}=1;
  $node{$t[1]}=1;
  if ($#t == 1) {
    $edge{"$t[0] $t[1]"}=1;
  } elsif ($#t == 2) {
    #$t[2] = $t[2]?0:1;
    $edge{"$t[0] $t[1] $t[2]"}=1;
  }
}
my $i=1;
open Fhandle, "> $out_pfx.node";
for (sort keys %node) {
  $node{$_}=$i;
  print Fhandle "$i $_\n";
  $i++;
}
close Fhandle;
open Fhandle, "> $out_pfx.edge";
for (sort keys %edge) {
  my @t = split / /, $_;
  if ($#t == 1) {
    print Fhandle "$node{$t[0]} $node{$t[1]}\n";
  } elsif ($#t == 2) {
    print Fhandle "$node{$t[0]} $node{$t[1]} $t[2]\n";
  }
}
close Fhandle;

