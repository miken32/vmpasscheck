#!/usr/bin/perl

#   vmpasscheck
#   A script to vailidate Asterisk voicemail passwords
#   Copyright (C) 2015 Point of Presence Technologies
#
#   This program is free software; you can redistribute it and/or modify
#   it under the terms of the GNU General Public License as published by
#   the Free Software Foundation; either version 2 of the License, or
#   (at your option) any later version.
#
#   This program is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#   GNU General Public License for more details.
#
#   You should have received a copy of the GNU General Public License along
#   with this program; if not, write to the Free Software Foundation, Inc.,
#   51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

#
# Usage:
#    vmpasscheck <mailbox> <context> <oldpass> <newpass>
# Results:
#    'VALID' on valid password
#    'INVALID' on invalid password
#    'FAILURE' on bad call (allows the password)
#
use strict;
use warnings;

use Sys::Syslog qw(:DEFAULT :standard :macros);

# Configuration
my $min_length        = 4;          # Minimum password length (Zero to disable)
my $check_consecutive = 3;          # Maximum number of consecutive digits allowed
my $check_same_digit  = 1;          # Check if password is one repeated digit
my $check_extension   = 1;          # Check if password and extension are the same
my $check_oldpass     = 1;          # Check if old and new passwords are the same
my $check_context     = 0;          # Check the the context is in the whitelist below
my @contexts          = (           # A list of contexts to enforce password validity on; others are skipped
    "default",
);
my $use_syslog        = 1;          # Enable syslog messages
my $priority          = LOG_INFO;   # Syslog priority to use
my $facility          = "local3";   # Syslog facility to use

# Subroutines
sub returnValid
{
    syslog($priority, "returnValid returns VALID") if $use_syslog;
    print "VALID\n";
    exit 0;
}

sub returnInvalid
{
    syslog($priority, "returnInvalid returns INVALID") if $use_syslog;
    print "INVALID\n";
    exit 65;
}

sub returnFailure
{
    syslog($priority, "returnFailure returns FAILURE") if $use_syslog;
    print "FAILURE\n";
    exit 64;
}

# Check parameters
my $mailbox;
my $context;
my $oldpass;
my $newpass;

if ($#ARGV == 3) {
    $mailbox = $ARGV[0];
    $context = $ARGV[1];
    $oldpass = $ARGV[2];
    $newpass = $ARGV[3];
    if ($use_syslog) {
        openlog("", "", $facility);
        syslog($priority, "Got: $mailbox $context $oldpass $newpass");
    }
} else {
    returnFailure;
}

# Check if context is validated or not
if ($check_context) {
    syslog($priority, "Checking for validation on context $context") if $use_syslog;
    returnValid unless (grep { $_ eq $context } @contexts);
}

# Check if password is long enough
if ($min_length) {
    syslog($priority, "Checking for length >= $min_length") if $use_syslog;
    returnInvalid if $min_length > length($newpass)
}

# Check if password is all consecutive numbers
if ($check_consecutive) {
    my $counter = 0;
    my $i  = 0;
    my @digits  = split(//, $newpass);
    my $pwlength = @digits;
    my %replacements = ("A", 65, "B", 66, "C", 67, "D", 68);

    s/(A|B|C|D)/$replacements{$1}/e for @digits;

    syslog($priority, "Checking for more than $check_consecutive consecutive digits") if $use_syslog;

    for ($i = 0; $i < $pwlength - 1; $i++) {
        $counter = ($digits[$i] + 1 == $digits[$i + 1]) ? $counter + 1 : 0;
        if ($counter >= $check_consecutive) {
            syslog($priority, "  Found $counter increasing consecutive numbers") if $use_syslog;
            returnInvalid;
        }
    }

    $counter = 0;
    for ($i = 0; $i < $pwlength - 1; $i++) {
        $counter = ($digits[$i] - 1 == $digits[$i + 1]) ? $counter + 1 : 0;
        if ($counter >= $check_consecutive) {
            syslog($priority, "  Found $counter increasing consecutive numbers") if $use_syslog;
            returnInvalid;
        }
    }
}

# Check if password is all one number
if ($check_same_digit) {
    syslog($priority, "Checking if password is all the same digit (1111, 3333, etc)") if $use_syslog;
    returnInvalid if ($newpass =~ /^(1+|2+|3+|4+|5+|6+|7+|8+|9+|0+|A+|B+|C+|D+)$/);
}

# Check if password is same as extension
if ($check_extension) {
    syslog($priority, "Checking if password is the same as the extension ($mailbox)") if $use_syslog;
    returnInvalid if ($mailbox eq $newpass);
}

# Check if password is same as old password
if ($check_oldpass) {
     syslog($priority, "Checking if password is the same as the old password ($oldpass)") if $use_syslog;
    returnInvalid if ($newpass eq $oldpass);
}

# Passed all the checks, it must be good
syslog($priority, "End of checks, returning default status.") if $use_syslog;
returnValid;

