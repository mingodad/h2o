use strict;
use warnings;
use Test::More;
use t::Util;

plan skip_all => 'g++ not found'
    unless prog_exists('g++');

my $ret = system("g++ -std=c++1y -DH2O_USE_SELECT=1 -D__c_as_cpp=1 -I deps/picohttpparser -I deps/yaml/include -I deps/yoml -I include include/h2o.h");
is $ret, 0, "compile h2o.h using g++";

done_testing;
