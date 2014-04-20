#!/usr/bin/perl

#
# This is an example of Perl script maintaining dynamic shared secret 
# database for the REST API
#

use strict;
use warnings;

use DBI;
use HTTP::Request::Common;

my $DBNAME="turn";
my $DBUSERNAME="turn";
my $DBPWD="turn";
my $DBHOST="localhost";

my $webserver = 'http://example.com/';

my $old_secret = "";
my $current_secret="";

my $INTERVAL=3600;

my $dbh;

$dbh = DBI->connect("DBI:mysql:$DBNAME;host=$DBHOST", $DBUSERNAME, $DBPWD)
	|| die "Could not connect to database: $DBI::errstr";
    
$dbh->do('CREATE TABLE IF NOT EXISTS turn_secret (value varchar(512))');

my $c = $dbh->do("delete from turn_secret");
print "Deleted $c rows\n";
    
$dbh->disconnect();

do {

    $dbh = DBI->connect("DBI:mysql:$DBNAME;host=$DBHOST", $DBUSERNAME, $DBPWD)
	|| die "Could not connect to database: $DBI::errstr";
    
    $dbh->do('CREATE TABLE IF NOT EXISTS turn_secret (value varchar(512))');

    if(length($current_secret)) {
	if(length($old_secret)) {
	    remove_secret($dbh, $old_secret);
	}
	$old_secret=$current_secret;
    }
    
    print "CURRENT SECRET TO BE (RE)GENERATED\n";
    $current_secret = generate_secret();
    insert_secret($dbh, $current_secret);
    
    $dbh->disconnect();

#
# Web server interaction example:
# Here we can put code to submit this secret to the web server:
#
    my $req = POST($webserver, Content => [param => $current_secret]);

    $req->method('PUT');

    print $req->as_string,"\n";

#
# Alternatively, you can use this link for compute-on-demand:
# https://github.com/alfreddatakillen/computeengineondemand
#
# write your code here.
#

    sleep($INTERVAL);

} while(1);

sub remove_secret {

    my $dbh = shift;
    my $secret=shift;

    my $c = $dbh->do("delete from turn_secret where value = '$secret'");
    print "Deleted $c rows\n";
   
}

sub insert_secret {

    my $dbh = shift;
    my $secret=shift;

    my $c = $dbh->do("insert into turn_secret values('$secret')");
    print "Inserted $c rows\n";
    
}

sub generate_secret {
    my @chars = ('0'..'9', 'A'..'F');
    my $len = 8;
    my $string;
    while($len--){ $string .= $chars[rand @chars] };
    return $string;
}
