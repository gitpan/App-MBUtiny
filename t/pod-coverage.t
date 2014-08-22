#!/usr/bin/perl -w
#########################################################################
#
# Serz Minus (Lepenkov Sergey), <minus@mail333.com>
#
# Copyright (C) 1998-2014 D&D Corporation. All Rights Reserved
# 
# This is free software; you can redistribute it and/or modify it
# under the same terms as Perl itself.
#
# $Id: pod-coverage.t 14 2014-08-22 18:20:31Z abalama $
#
#########################################################################

use Test::More;
eval "use Test::Pod::Coverage 1.08";
plan skip_all => "Test::Pod::Coverage required for testing POD coverage" if $@;
plan skip_all => "Currently a developer-only test" unless -d '.svn' || -d ".git";
plan tests => 2;

pod_coverage_ok( "App::MBUtiny", { trustme => [qr/^(get_jobs|get_dates)$/] } );
pod_coverage_ok( "App::MBUtiny::CopyExclusive" );

1;
