#!/usr/bin/perl -w

############### malbait #############

#OK, is good! 

#Now, add ICMP support!



use IO::Socket;
use Fcntl qw/:DEFAULT :flock/;


use strict;

no warnings;

my $counter = 0;
my $printable_ports;

my $current_port_in_range;
my $port_range_count;
my $last_port_in_range;
my @port_array;
my $use_default_protocol;

my $wait_input;

my $nmap_scan;
my $nmap_whois_report;

my $whois_option;
my $whois_scan;

my $socket;
my $read_socket;

my $protocol;

my $server_port;
my $server_output;
my $client_output;

my $client_data;
my $client_chr_data;
my $chr_data_report;
my $verbal_report;
my $report_filename = "malbait-report-";


my @custom_conversation;
my $custom_prompt;

my @client_conversation;
my $count_conversation = 0;
my $conversation_report;


my $client_socket;
my $send_test;
my $output_count;
my $test_variable;

#### Experiment with forking  ####
my $timeleft = 1;
my $parent_pid;
my $mypid;
my $procid;
##########################

my $catch_timeout;


####### inputs and options #######################
my @input = @ARGV;

my @input_matches;

my $input_protocol;
my $input_banner;
my $input_port;
my $input_nmap;
my $noloop;
my $notrans;
my $transblank;
my $crlf;
my $blocking = 1;
my $recv_buffer = 1024;
my $report_option;
my $timeout = 30;
my $verbose_option;

my $transport_protocol;
my $transport_protocol_option;
my $max_requests_per_server = 2;
my $saved_transport_protocol;

############## Looping: #############
my $looptimes;
my $all_defaults;
#####################################


#############Time:############
my $time;
############################## VALIDATE INPUTS ################################


if (scalar @input <1)	{
	PrintUsagePage();
	die "\n";
}



@input_matches = grep { /-help/} @input;
if ($input_matches[0] =~ '-help')	{
	PrintUsagePage();
	die "\n";
}

@input_matches = grep { /-gpl/} @input;
if ($input_matches[0] =~ '-gpl')	{
	PrintGPL();
}


@input_matches = grep { /-defaults/} @input;
if ($input_matches[0] =~ '-defaults')	{
	print "\n DEFAULT MODE. Will generate a set of UDP and TCP servers.";
	$all_defaults = "YES"
}

my $command = "";
my $email_mode;
my $cmd;
my $email_password;
my $email_temp;

my $from_address;
my $to_address;
my $smtp_server;
my $smtp_port;

my @email_data;
my $email_floop;

@input_matches = grep { /-email_pass:/} @input;
if ($input_matches[0] =~ '-email_pass:')	{
	$email_mode = "True";
	$email_floop = 0;
	print ("Email mode selected. Password:");
	$email_password = substr ($input_matches[0], 12); 
	print $email_password;
	print ("\n");
	open EMAIL, "emaildata.txt" or die "\n\nReality failure error. Couldn't open emaildata.txt.\n\n";
	while (<EMAIL>)	{
		$email_temp .= $_;
		chomp ($_);
		@email_data[$email_floop] = $_;
		$email_floop ++;
	}
	$from_address = @email_data[0];
	$to_address = @email_data[1];
	$smtp_server = @email_data[2];
	$smtp_port = @email_data[3];
	
	print "\n$from_address";
	print "\n$to_address";
	print "\n$smtp_server";
	print "\n$smtp_port";
	print "\n\n email_mode: $email_mode";
}
	
	#	$cmd = "mail_report.py ";  
	#	$cmd .= $from_address;
	#	$cmd .= " ";
	#	$cmd .= $to_address;
	#	$cmd .= " ";
	#	$cmd .= $smtp_server;
	#	$cmd .= " ";
	#	$cmd .= $smtp_port;
	#	$cmd .= " ";
	#	$cmd .= $email_password;
	#	$cmd .= " ";



@input_matches = grep { /-maxreq:/} @input;
if ($input_matches[0] =~ '-maxreq:')	{
	print "\n Multiplexing ON. Requests allowed per server: ";
	$max_requests_per_server = (substr  $input_matches[0], 8);
	print $max_requests_per_server;
}


@input_matches = grep { /-no_multiplexing/} @input;
if ($input_matches[0] =~ '-no_multiplexing')	{
	print "\n Multiplexing OFF. Will NOT spawn each server in its own process (NOT RECCOMENDED) ";
	undef $max_requests_per_server;
}


@input_matches = grep { /-trans_proto:/} @input;
if ($input_matches[0] =~ '-trans_proto:')	{
	print "\n Transport protocol selection:";
	$transport_protocol = lc (substr ($input_matches[0], 13));
	$saved_transport_protocol = $transport_protocol;
	print "$transport_protocol";
	unless ($transport_protocol eq 'tcp' ||
			$transport_protocol eq 'udp' ||
			$transport_protocol eq 'tcpudp'
			)	{
		print "\n *** ERROR! You didn't enter the *correct* -trans_proto: option  **** ";
		print "\n Acceptable usage is: ";
		print "\n\n \t perl malbait.pl -trans_proto:tcp";
		print "\n \t perl malbait.pl -trans_proto:udp ";
		print "\n \t perl malbait.pl -trans_proto:tcpudp ";
		print "\n\n";
		die "\n";
	}
}

@input_matches = grep { /-waitinput/} @input;
if ($input_matches[0] =~ '-waitinput')	{
	print "\n -waitinput option selected.";
	print "\n I will wait for client to say something before I transmit";
	$wait_input = "ON";
}

@input_matches = grep { /-proto:/} @input;
if ($input_matches[0] =~ '-proto:')	{
	print "\n Protocol selection:";
	$input_protocol = substr ($input_matches[0] ,7);
	$protocol = $input_protocol;
	print "$protocol\n";

	unless ($protocol eq 'imap' ||
			$protocol eq 'ftp' ||
			$protocol eq 'telnet' ||
			$protocol eq 'smtp' ||
			$protocol eq 'http' ||
			$protocol eq 'pop3' ||
			$protocol eq 'tr-69' ||
			$protocol eq "bgp" ||
			$protocol eq 'fuzz' ||
			$protocol eq 'notrans' ||
			$protocol eq 'transblank' ||
			$protocol eq 'asciitime' ||
			#$protocol eq 'bittime' ||
			$protocol eq 'hacktime-2036' ||
			$protocol eq 'hacktime-1900' ||
			$protocol eq 'systat' ||
			$protocol eq 'echo' )	{
		print "\n *** ERROR! You didn't enter the *correct* -proto: option  **** ";
		print "\n Acceptable usage is: ";
		print "\n\n \t perl malbait.pl -proto:imap ";
		print "\n \t perl malbait.pl -proto:ftp ";
		print "\n \t perl malbait.pl -proto:telnet ";
		print "\n \t perl malbait.pl -proto:smtp ";
		print "\n \t perl malbait.pl -proto:http ";
		print "\n \t perl malbait.pl -proto:pop3 ";
		print "\n \t perl malbait.pl -proto:tr-69 ";
		print "\n \t perl malbait.pl -proto:bgp ";
		print "\n \t perl malbait.pl -proto:fuzz -port:nn ";
		print "\n \t perl malbait.pl -proto:notrans -port:nn ";
		print "\n \t perl malbait.pl -proto:transblank -port:nn ";
		print "\n \t perl malbait.pl -proto:asciitime ";
		#print "\n \t perl malbait.pl -proto:bittime ";
		print "\n \t perl malbait.pl -proto:asciitime ";
		print "\n \t perl malbait.pl -proto:hacktime-2036 ";
		print "\n \t perl malbait.pl -proto:hacktime-1900 ";
		print "\n \t perl malbait.pl -proto:systat ";
		print "\n \t perl malbait.pl -proto:echo ";
		print "\n DON'T FORGET TO ADD SAMBA SUPPORT (default ports 339, 445...)";
		print "\n\n";
		die "\n";
	}
}

if (defined $protocol)	{
	print "\n Assuming we're running, we've selected protocol $protocol, overriding defaults";
}
else	{
	print "\n Protocol NOT selected by user, will select appropriate protocol by port. \n";
}


@input_matches = grep { /-verbose/ } @input;
if ($input_matches[0] eq '-verbose')	{
	$verbose_option = "ON";
	print "\n verbose option selected - tons of analysis data will be displayed";
}



@input_matches = grep { /-port:/||/-ports:/ } @input;

if ($input_matches[0] =~ '-port:')	{
	$port_array[0] = substr($input_matches[0], 6);
	print "\n Server port is $port_array[0]\n";
	$printable_ports = $port_array[0];
	if (length($port_array[0] <1)) {die "\n\nFATAL ERRROR: You used the -port: option but didn't input an actual port number. \n";}
}
elsif ($input_matches[0] =~ '-ports:')	{
	print "\n Multiple ports to be opened: \n";
	$input_matches[0] = substr($input_matches[0], 7);

	print "\n\n Input: $input_matches[0] \n ";
	if ($input_matches[0] =~ '-')	{
		@port_array = split '-', $input_matches[0];
		if (scalar @port_array > 2)	{
			die "\n ERROR! You entered too many '-' characters. \n\t Usage: -ports:xx-yy or -ports:xx,yy,zz \n\n";

		}
		until ($counter == scalar (@port_array) ) {
			$printable_ports .= $port_array[$counter]."-";
			$counter++;
			print "\n Printable ports: $printable_ports \n";
		}
		chop $printable_ports;
		print "\n Port range selected:";
			# Make it actually put all those ports in port_array...
		print "$port_array[0] - $port_array[1]";
		$current_port_in_range = $port_array[0];
		$last_port_in_range = $port_array[1];
		$port_range_count = 0;
		print "\n Spooling port range...\n";
		until ($current_port_in_range > $last_port_in_range)	{
			$port_array[$port_range_count] = $current_port_in_range;
			print "\n port_range_count:$port_range_count \t current_port_in_range: $current_port_in_range";
			$port_range_count++;
			$current_port_in_range++;
		}
	}

	elsif ($input_matches[0] =~ ',')	{
		print "\n Port list selected:";
		@port_array = split ',', $input_matches[0];
		print "\n @port_array\n";
		$counter = 0;
		until ($counter == scalar (@port_array) ) {
			$printable_ports .= $port_array[$counter].",";
			$counter++;
			print "\n Printable ports: $printable_ports \n";
		}
		chop $printable_ports;
	}
	print "\n Printable ports: $printable_ports \n";
}


@input_matches = grep { /-report:/ } @input;
if ($input_matches[0] =~ '-report:') {
	print "\n -report: option selected.";
	$report_option = "ON";
	$report_filename = substr ($input_matches[0], 8);
	print "\n \$report_option is $report_option. Will write reports to $report_filename";
	print "\n";
}
else	{
	$report_filename = $report_filename.$protocol.$printable_ports.".txt";
	print "\n Will write report to $report_filename";
}

print "\n\n\n";


@input_matches = grep { /-whois/ } @input;
if ($input_matches[0] eq '-whois')	{
	$whois_scan = "ON";
	$nmap_whois_report = "NmapWhoisReport-$protocol-$server_port.txt";
	print "\n Whois option selected - a whois report will be placed in the NmapWhois report file";
	print "\n";
}
else {
	print "\n Whois scan will NOT be performed...";
}


@input_matches = grep { /-nmap/ } @input;
if ($input_matches[0] eq '-nmap')	{
	$nmap_scan = "ON";
}

if ($nmap_scan)	{
	print "\n nmap scan is defined.";
	print "\n nmap_scan is $nmap_scan \n\n";
	$nmap_whois_report = "NmapWhoisReport-$protocol-$server_port.txt";
	print "\n The nmap report will be written to $nmap_whois_report ";

}
else	{
	print "\n nmap_scan is not defined, so client will not be nmapped.";
}

@input_matches = grep { /-noloop/ } @input;
if ($input_matches[0] eq '-noloop')	{
	print "-noloop option selected. This program will accept one connection, once, then die.";
	$noloop = "YES";
}
else	{
	print "\n -noloop option NOT selected, this program will loop infinitely until you break out of it with CTRL-C or kill it (but why would you wanna do that? \n";
}

@input_matches = grep { /-notrans/ } @input;
if ($input_matches[0] eq '-notrans') {
	die "\n\n This option has been depracated. Use -proto:transblank instead.\n\n";
}

@input_matches = grep { /-transblank/ } @input;
if ($input_matches[0] eq '-transblank') {
	print "\n -transblank option selected. This program will transmit carraige return characters, even on ports with a protocol associated with it.";
	$transblank = "ON";
}


@input_matches = grep { /-noblocking/ } @input;
if ($input_matches[0] eq '-noblocking')	{
	print "\n -noblocking option selected. Blocking will be switched OFF. ";
	print "\n";
	$blocking = 0;		# It's 0 and not "NO" because that's how IO::Socket::INET likes it!
}

@input_matches = grep { /-recvbuffer:/ } @input;
if ($input_matches[0] =~ '-recvbuffer:') {
	print "\n -recvbuffer:nn option selected.";
	$recv_buffer = substr ($input_matches[0], 12);
	print "\n The recv buffer has been set to $recv_buffer ";
	print "\n";
}

@input_matches = grep { /-timeout:/ } @input;
if ($input_matches[0] =~ '-timeout:') {
	print "\n -timeout: option selected.";
	$timeout = substr ($input_matches[0], 9);
	print "\n Timeout set to $timeout";
	print "\n";
}


print "\n *******************************************************";
print "\n *                                                     *";
print "\n * TRANSPORT PROTOCOL:$transport_protocol                      *";
print "\n *                                                     *";
print "\n *******************************************************";
##sleep 1;



########################## START THE FUN! ##############################


if ($transport_protocol eq 'tcpudp')	{
	$transport_protocol = 'tcp';
	$saved_transport_protocol = $transport_protocol;
	my $listener = new ListenObject (
							ReportFilename => $report_filename,
							TransportProtocol => $transport_protocol,
							WaitInput => $wait_input,
							Protocol => $protocol,
							PortArrayRef => \@port_array,
							UseDefaultProtocol => $use_default_protocol,
							WhoisScan => $whois_scan,
							NmapScan => $nmap_scan,
							NmapWhoisReport => $nmap_whois_report,
							NoLoop => $noloop,
							Blocking => $blocking,
							RecvBuffer => $recv_buffer,
							Timeout => $timeout,
							MaxRequestsPerServer => $max_requests_per_server,
							SavedTransportProtocol => $saved_transport_protocol,
							AllDefaults => $all_defaults,
							Transblank => $transblank
							);
	$transport_protocol = 'udp';
	$saved_transport_protocol = $transport_protocol;
	my $listener = new ListenObject (
							ReportFilename => $report_filename,
							TransportProtocol => $transport_protocol,
							WaitInput => $wait_input,
							Protocol => $protocol,
							PortArrayRef => \@port_array,
							UseDefaultProtocol => $use_default_protocol,
							WhoisScan => $whois_scan,
							NmapScan => $nmap_scan,
							NmapWhoisReport => $nmap_whois_report,
							NoLoop => $noloop,
							Blocking => $blocking,
							RecvBuffer => $recv_buffer,
							Timeout => $timeout,
							MaxRequestsPerServer => $max_requests_per_server,
							SavedTransportProtocol => $saved_transport_protocol,
							AllDefaults => $all_defaults,
							Transblank => $transblank
							);
}
else {
	my $listener = new ListenObject (
							ReportFilename => $report_filename,
							TransportProtocol => $transport_protocol,
							WaitInput => $wait_input,
							Protocol => $protocol,
							PortArrayRef => \@port_array,
							UseDefaultProtocol => $use_default_protocol,
							WhoisScan => $whois_scan,
							NmapScan => $nmap_scan,
							NmapWhoisReport => $nmap_whois_report,
							NoLoop => $noloop,
							Blocking => $blocking,
							RecvBuffer => $recv_buffer,
							Timeout => $timeout,
							MaxRequestsPerServer => $max_requests_per_server,
							SavedTransportProtocol => $saved_transport_protocol,
							AllDefaults => $all_defaults,
							Transblank => $transblank
							);
}





print "\n\n Bye! \n\n";
die "\n\n That's all, folks!\n\n";


###########################################################################
###################### SUBROUTINES ########################################
###########################################################################



##################################################################################################
################################  BEHAVIOURWARNING ############################################
##################################################################################################

sub BehaviourWarning()	{
	print "\n  ********************************************************************";
	print "\n  **** WARNING **    ** WARNING **    ** WARNING **    ** WARNING ****";
	print "\n  **** This option can cause unpredictable behaviour. Be ready to ****";
	print "\n  **** hit CTRL-C and relaunch this program at VERY SHORT NOTICE. ****";
	print "\n  ********************************************************************";
}

##################################################################################################
#################################### PRINTUSAGEPAGE ###########################################
##################################################################################################

sub PrintUsagePage	{
	print "\n\n \t *** MALBAIT - A PERL HONEYPOT *** ";
	print "\n";
	print "\n Usage: ";
	print "\n";
	print "\n -email_pass: blahblah \t Activates EMAIL MODE. Enter password after \"-email_pass:\", load other email info from emaildata.txt";
	print "\n";
	
	print "\n -ports:xxx-yyy \t Selects range of ports to watch.";
	#print "\n ";
	print "\n -ports:xx,yy,zz \t Selects list of ports to watch.";
	#print "\n";
	print "\n -port:nn \t \t select single port to watch.";
	print "\n ";
	print "\n -proto:  select protocol \n (will autoselect from port numbers if not used) ";
	print "\n   -proto:ftp \t\t defaults to ports 20,21,69,115,152";
	print "\n   -proto:smtp \t\t defaults to ports 25,465,587,2525,2526";
	print "\n   -proto:telnet\t defaults to ports 23,107,123,992,12323,2323,2345, 9999";
	print "\n   -proto:pop3 \t\t defaults to ports 110,995";
	print "\n   -proto:http \t\t defaults to ports 80,8080,81";
	print "\n   -proto:tr-69 \t defaults to port 7547";
	print "\n   -proto:bgp \t\t defaults to port 179";
	print "\n   -proto:imap \t\t defaults to ports 143,993";
	print "\n   -proto:asciitime \t defaults to port 13";
	print "\n   -proto:systat \t defaults to port 11";
	print "\n   -proto:echo \t\t defaults to port 7";
	print "\n   -proto:fuzz  \t NO DEFAULT PORT. Transmit random garbage to clients.";
	print "\n   -proto:transblank \t NO DEFAULT PORT. Transmits whitespace (CR) to clients";
	print "\n   -proto:hacktime-2036\t Creates an NTP server and sends all FFs through it";
	print "\n   -proto:hacktime-1900\t Creates an NTP server and sends all 01s through it";
	print "\n";
	print "\n  NB for -proto:fuzz and -proto:transblank options you MUST specify port with -port or -ports";
	print "\n ";
	print "\n -waitinput  Wait for input before transmitting";
	print "\n";
#	print "\n";
#	print "\n  -banner: \t select banner. FTP, POP3 and SMTP already have default banners which can be overridden(?)";
	print "\n  -transblank  As -proto:transblank. Transmits blank responses (CR characters).";
#	print "\n";
	print "\n -nmap: Scan each client with nmap after each session. Output goes in a ";
	print "seperate file- not always reliable and the results aren't always pretty but it's ";
	print "a quick n dirty way to get information. Warning: If a UDP client stays on it WILL nmap ";
	print "them repeatedly. Results go in NmapWhoisReport-blah.txt.";
	print "\n";
	print "\n -whois: Does a WHOIS query on all clients. Warning: It WILL operate repeatedly on ";
	print "UDP clients that remain connected. Results go in NmapWhoisReport-blah.txt.";
	print "\n";
	print "\n -noloop\t Don't loop (ie, stop each server after one connection).";
	print "\n -no_multiplexing \t Turn off multiplexing to save memory (not reccomended)";
	print "\n -noblocking:\t Turn off blocking mode. Very useful for telnet stuff";
	print "\n -maxreq:nn:\t Allows nn connections per server. Default is 2.";
	print "\n -timeout:n:\t Set the timeout for clients to n seconds. Default is 30";
	print "\n -report:filename.txt:\t Sets the report file to filename.txt";
	print "\n -recvbuffer:nn: Set the recv buffer to value nn. Default is 1024.";
	print "\n -trans_proto:xxx:Can be tcp, udp or tcpudp for both. Defaults to tcp";
	print "\n -defaults:\t Runs with default options- Helpful for beginners...";
	print "\n -gpl:\t General Public Licence boilerplate info.";
	print "\n";
	print "\n NOTE: THIS PROGRAM SHOULD BE RUN IN SUPERUSER MODE.";
	print "\n If you get an error message, try 'sudo malbait' (or 'sudo perl malbait.pl')\n";
	print "\n";
	print "\n Please send yer bitcoin to: 16P267RxgkLsEDVEKwLGsfnUCJ6bfgyWKR ";
	print "\n ";
	print "\n As of September 2017 I can still be contacted at batchmcnulty\@protonmail.com.";
	print "\n\n";
}


##################################### PrintGPL ##################################

sub PrintGPL	{

	print "\n";
	print '  GNU GENERAL PUBLIC LICENSE
                       Version 3, 29 June 2007

 Copyright (C) 2007 Free Software Foundation, Inc. <http://fsf.org/>
 Everyone is permitted to copy and distribute verbatim copies
 of this license document, but changing it is not allowed.

                            Preamble

  The GNU General Public License is a free, copyleft license for
software and other kinds of works.

  The licenses for most software and other practical works are designed
to take away your freedom to share and change the works.  By contrast,
the GNU General Public License is intended to guarantee your freedom to
share and change all versions of a program--to make sure it remains free
software for all its users.  We, the Free Software Foundation, use the
GNU General Public License for most of our software; it applies also to
any other work released this way by its authors.  You can apply it to
your programs, too.

  When we speak of free software, we are referring to freedom, not
price.  Our General Public Licenses are designed to make sure that you
have the freedom to distribute copies of free software (and charge for
them if you wish), that you receive source code or can get it if you
want it, that you can change the software or use pieces of it in new
free programs, and that you know you can do these things.

  To protect your rights, we need to prevent others from denying you
these rights or asking you to surrender the rights.  Therefore, you have
certain responsibilities if you distribute copies of the software, or if
you modify it: responsibilities to respect the freedom of others.

  For example, if you distribute copies of such a program, whether
gratis or for a fee, you must pass on to the recipients the same
freedoms that you received.  You must make sure that they, too, receive
or can get the source code.  And you must show them these terms so they
know their rights.

  Developers that use the GNU GPL protect your rights with two steps:
(1) assert copyright on the software, and (2) offer you this License
giving you legal permission to copy, distribute and/or modify it.

  For the developers\' and authors\' protection, the GPL clearly explains
that there is no warranty for this free software.  For both users\' and
authors\' sake, the GPL requires that modified versions be marked as
changed, so that their problems will not be attributed erroneously to
authors of previous versions.

  Some devices are designed to deny users access to install or run
modified versions of the software inside them, although the manufacturer
can do so.  This is fundamentally incompatible with the aim of
protecting users\' freedom to change the software.  The systematic
pattern of such abuse occurs in the area of products for individuals to
use, which is precisely where it is most unacceptable.  Therefore, we
have designed this version of the GPL to prohibit the practice for those
products.  If such problems arise substantially in other domains, we
stand ready to extend this provision to those domains in future versions
of the GPL, as needed to protect the freedom of users.

  Finally, every program is threatened constantly by software patents.
States should not allow patents to restrict development and use of
software on general-purpose computers, but in those that do, we wish to
avoid the special danger that patents applied to a free program could
make it effectively proprietary.  To prevent this, the GPL assures that
patents cannot be used to render the program non-free.

  The precise terms and conditions for copying, distribution and
modification follow.

                       TERMS AND CONDITIONS

  0. Definitions.

  "This License" refers to version 3 of the GNU General Public License.

  "Copyright" also means copyright-like laws that apply to other kinds of
works, such as semiconductor masks.

  "The Program" refers to any copyrightable work licensed under this
License.  Each licensee is addressed as "you".  "Licensees" and
"recipients" may be individuals or organizations.

  To "modify" a work means to copy from or adapt all or part of the work
in a fashion requiring copyright permission, other than the making of an
exact copy.  The resulting work is called a "modified version" of the
earlier work or a work "based on" the earlier work.

  A "covered work" means either the unmodified Program or a work based
on the Program.

  To "propagate" a work means to do anything with it that, without
permission, would make you directly or secondarily liable for
infringement under applicable copyright law, except executing it on a
computer or modifying a private copy.  Propagation includes copying,
distribution (with or without modification), making available to the
public, and in some countries other activities as well.

  To "convey" a work means any kind of propagation that enables other
parties to make or receive copies.  Mere interaction with a user through
a computer network, with no transfer of a copy, is not conveying.

  An interactive user interface displays "Appropriate Legal Notices"
to the extent that it includes a convenient and prominently visible
feature that (1) displays an appropriate copyright notice, and (2)
tells the user that there is no warranty for the work (except to the
extent that warranties are provided), that licensees may convey the
work under this License, and how to view a copy of this License.  If
the interface presents a list of user commands or options, such as a
menu, a prominent item in the list meets this criterion.

  1. Source Code.

  The "source code" for a work means the preferred form of the work
for making modifications to it.  "Object code" means any non-source
form of a work.

  A "Standard Interface" means an interface that either is an official
standard defined by a recognized standards body, or, in the case of
interfaces specified for a particular programming language, one that
is widely used among developers working in that language.

  The "System Libraries" of an executable work include anything, other
than the work as a whole, that (a) is included in the normal form of
packaging a Major Component, but which is not part of that Major
Component, and (b) serves only to enable use of the work with that
Major Component, or to implement a Standard Interface for which an
implementation is available to the public in source code form.  A
"Major Component", in this context, means a major essential component
(kernel, window system, and so on) of the specific operating system
(if any) on which the executable work runs, or a compiler used to
produce the work, or an object code interpreter used to run it.

  The "Corresponding Source" for a work in object code form means all
the source code needed to generate, install, and (for an executable
work) run the object code and to modify the work, including scripts to
control those activities.  However, it does not include the work\'s
System Libraries, or general-purpose tools or generally available free
programs which are used unmodified in performing those activities but
which are not part of the work.  For example, Corresponding Source
includes interface definition files associated with source files for
the work, and the source code for shared libraries and dynamically
linked subprograms that the work is specifically designed to require,
such as by intimate data communication or control flow between those
subprograms and other parts of the work.

  The Corresponding Source need not include anything that users
can regenerate automatically from other parts of the Corresponding
Source.

  The Corresponding Source for a work in source code form is that
same work.

  2. Basic Permissions.

  All rights granted under this License are granted for the term of
copyright on the Program, and are irrevocable provided the stated
conditions are met.  This License explicitly affirms your unlimited
permission to run the unmodified Program.  The output from running a
covered work is covered by this License only if the output, given its
content, constitutes a covered work.  This License acknowledges your
rights of fair use or other equivalent, as provided by copyright law.

  You may make, run and propagate covered works that you do not
convey, without conditions so long as your license otherwise remains
in force.  You may convey covered works to others for the sole purpose
of having them make modifications exclusively for you, or provide you
with facilities for running those works, provided that you comply with
the terms of this License in conveying all material for which you do
not control copyright.  Those thus making or running the covered works
for you must do so exclusively on your behalf, under your direction
and control, on terms that prohibit them from making any copies of
your copyrighted material outside their relationship with you.

  Conveying under any other circumstances is permitted solely under
the conditions stated below.  Sublicensing is not allowed; section 10
makes it unnecessary.

  3. Protecting Users\' Legal Rights From Anti-Circumvention Law.

  No covered work shall be deemed part of an effective technological
measure under any applicable law fulfilling obligations under article
11 of the WIPO copyright treaty adopted on 20 December 1996, or
similar laws prohibiting or restricting circumvention of such
measures.

  When you convey a covered work, you waive any legal power to forbid
circumvention of technological measures to the extent such circumvention
is effected by exercising rights under this License with respect to
the covered work, and you disclaim any intention to limit operation or
modification of the work as a means of enforcing, against the work\'s
users, your or third parties\' legal rights to forbid circumvention of
technological measures.

  4. Conveying Verbatim Copies.

  You may convey verbatim copies of the Program\'s source code as you
receive it, in any medium, provided that you conspicuously and
appropriately publish on each copy an appropriate copyright notice;
keep intact all notices stating that this License and any
non-permissive terms added in accord with section 7 apply to the code;
keep intact all notices of the absence of any warranty; and give all
recipients a copy of this License along with the Program.

  You may charge any price or no price for each copy that you convey,
and you may offer support or warranty protection for a fee.

  5. Conveying Modified Source Versions.

  You may convey a work based on the Program, or the modifications to
produce it from the Program, in the form of source code under the
terms of section 4, provided that you also meet all of these conditions:

    a) The work must carry prominent notices stating that you modified
    it, and giving a relevant date.

    b) The work must carry prominent notices stating that it is
    released under this License and any conditions added under section
    7.  This requirement modifies the requirement in section 4 to
    "keep intact all notices".

    c) You must license the entire work, as a whole, under this
    License to anyone who comes into possession of a copy.  This
    License will therefore apply, along with any applicable section 7
    additional terms, to the whole of the work, and all its parts,
    regardless of how they are packaged.  This License gives no
    permission to license the work in any other way, but it does not
    invalidate such permission if you have separately received it.

    d) If the work has interactive user interfaces, each must display
    Appropriate Legal Notices; however, if the Program has interactive
    interfaces that do not display Appropriate Legal Notices, your
    work need not make them do so.

  A compilation of a covered work with other separate and independent
works, which are not by their nature extensions of the covered work,
and which are not combined with it such as to form a larger program,
in or on a volume of a storage or distribution medium, is called an
"aggregate" if the compilation and its resulting copyright are not
used to limit the access or legal rights of the compilation\'s users
beyond what the individual works permit.  Inclusion of a covered work
in an aggregate does not cause this License to apply to the other
parts of the aggregate.

  6. Conveying Non-Source Forms.

  You may convey a covered work in object code form under the terms
of sections 4 and 5, provided that you also convey the
machine-readable Corresponding Source under the terms of this License,
in one of these ways:

    a) Convey the object code in, or embodied in, a physical product
    (including a physical distribution medium), accompanied by the
    Corresponding Source fixed on a durable physical medium
    customarily used for software interchange.

    b) Convey the object code in, or embodied in, a physical product
    (including a physical distribution medium), accompanied by a
    written offer, valid for at least three years and valid for as
    long as you offer spare parts or customer support for that product
    model, to give anyone who possesses the object code either (1) a
    copy of the Corresponding Source for all the software in the
    product that is covered by this License, on a durable physical
    medium customarily used for software interchange, for a price no
    more than your reasonable cost of physically performing this
    conveying of source, or (2) access to copy the
    Corresponding Source from a network server at no charge.

    c) Convey individual copies of the object code with a copy of the
    written offer to provide the Corresponding Source.  This
    alternative is allowed only occasionally and noncommercially, and
    only if you received the object code with such an offer, in accord
    with subsection 6b.

    d) Convey the object code by offering access from a designated
    place (gratis or for a charge), and offer equivalent access to the
    Corresponding Source in the same way through the same place at no
    further charge.  You need not require recipients to copy the
    Corresponding Source along with the object code.  If the place to
    copy the object code is a network server, the Corresponding Source
    may be on a different server (operated by you or a third party)
    that supports equivalent copying facilities, provided you maintain
    clear directions next to the object code saying where to find the
    Corresponding Source.  Regardless of what server hosts the
    Corresponding Source, you remain obligated to ensure that it is
    available for as long as needed to satisfy these requirements.

    e) Convey the object code using peer-to-peer transmission, provided
    you inform other peers where the object code and Corresponding
    Source of the work are being offered to the general public at no
    charge under subsection 6d.

  A separable portion of the object code, whose source code is excluded
from the Corresponding Source as a System Library, need not be
included in conveying the object code work.

  A "User Product" is either (1) a "consumer product", which means any
tangible personal property which is normally used for personal, family,
or household purposes, or (2) anything designed or sold for incorporation
into a dwelling.  In determining whether a product is a consumer product,
doubtful cases shall be resolved in favor of coverage.  For a particular
product received by a particular user, "normally used" refers to a
typical or common use of that class of product, regardless of the status
of the particular user or of the way in which the particular user
actually uses, or expects or is expected to use, the product.  A product
is a consumer product regardless of whether the product has substantial
commercial, industrial or non-consumer uses, unless such uses represent
the only significant mode of use of the product.

  "Installation Information" for a User Product means any methods,
procedures, authorization keys, or other information required to install
and execute modified versions of a covered work in that User Product from
a modified version of its Corresponding Source.  The information must
suffice to ensure that the continued functioning of the modified object
code is in no case prevented or interfered with solely because
modification has been made.

  If you convey an object code work under this section in, or with, or
specifically for use in, a User Product, and the conveying occurs as
part of a transaction in which the right of possession and use of the
User Product is transferred to the recipient in perpetuity or for a
fixed term (regardless of how the transaction is characterized), the
Corresponding Source conveyed under this section must be accompanied
by the Installation Information.  But this requirement does not apply
if neither you nor any third party retains the ability to install
modified object code on the User Product (for example, the work has
been installed in ROM).

  The requirement to provide Installation Information does not include a
requirement to continue to provide support service, warranty, or updates
for a work that has been modified or installed by the recipient, or for
the User Product in which it has been modified or installed.  Access to a
network may be denied when the modification itself materially and
adversely affects the operation of the network or violates the rules and
protocols for communication across the network.

  Corresponding Source conveyed, and Installation Information provided,
in accord with this section must be in a format that is publicly
documented (and with an implementation available to the public in
source code form), and must require no special password or key for
unpacking, reading or copying.

  7. Additional Terms.

  "Additional permissions" are terms that supplement the terms of this
License by making exceptions from one or more of its conditions.
Additional permissions that are applicable to the entire Program shall
be treated as though they were included in this License, to the extent
that they are valid under applicable law.  If additional permissions
apply only to part of the Program, that part may be used separately
under those permissions, but the entire Program remains governed by
this License without regard to the additional permissions.

  When you convey a copy of a covered work, you may at your option
remove any additional permissions from that copy, or from any part of
it.  (Additional permissions may be written to require their own
removal in certain cases when you modify the work.)  You may place
additional permissions on material, added by you to a covered work,
for which you have or can give appropriate copyright permission.

  Notwithstanding any other provision of this License, for material you
add to a covered work, you may (if authorized by the copyright holders of
that material) supplement the terms of this License with terms:

    a) Disclaiming warranty or limiting liability differently from the
    terms of sections 15 and 16 of this License; or

    b) Requiring preservation of specified reasonable legal notices or
    author attributions in that material or in the Appropriate Legal
    Notices displayed by works containing it; or

    c) Prohibiting misrepresentation of the origin of that material, or
    requiring that modified versions of such material be marked in
    reasonable ways as different from the original version; or

    d) Limiting the use for publicity purposes of names of licensors or
    authors of the material; or

    e) Declining to grant rights under trademark law for use of some
    trade names, trademarks, or service marks; or

    f) Requiring indemnification of licensors and authors of that
    material by anyone who conveys the material (or modified versions of
    it) with contractual assumptions of liability to the recipient, for
    any liability that these contractual assumptions directly impose on
    those licensors and authors.

  All other non-permissive additional terms are considered "further
restrictions" within the meaning of section 10.  If the Program as you
received it, or any part of it, contains a notice stating that it is
governed by this License along with a term that is a further
restriction, you may remove that term.  If a license document contains
a further restriction but permits relicensing or conveying under this
License, you may add to a covered work material governed by the terms
of that license document, provided that the further restriction does
not survive such relicensing or conveying.

  If you add terms to a covered work in accord with this section, you
must place, in the relevant source files, a statement of the
additional terms that apply to those files, or a notice indicating
where to find the applicable terms.

  Additional terms, permissive or non-permissive, may be stated in the
form of a separately written license, or stated as exceptions;
the above requirements apply either way.

  8. Termination.

  You may not propagate or modify a covered work except as expressly
provided under this License.  Any attempt otherwise to propagate or
modify it is void, and will automatically terminate your rights under
this License (including any patent licenses granted under the third
paragraph of section 11).

  However, if you cease all violation of this License, then your
license from a particular copyright holder is reinstated (a)
provisionally, unless and until the copyright holder explicitly and
finally terminates your license, and (b) permanently, if the copyright
holder fails to notify you of the violation by some reasonable means
prior to 60 days after the cessation.

  Moreover, your license from a particular copyright holder is
reinstated permanently if the copyright holder notifies you of the
violation by some reasonable means, this is the first time you have
received notice of violation of this License (for any work) from that
copyright holder, and you cure the violation prior to 30 days after
your receipt of the notice.

  Termination of your rights under this section does not terminate the
licenses of parties who have received copies or rights from you under
this License.  If your rights have been terminated and not permanently
reinstated, you do not qualify to receive new licenses for the same
material under section 10.

  9. Acceptance Not Required for Having Copies.

  You are not required to accept this License in order to receive or
run a copy of the Program.  Ancillary propagation of a covered work
occurring solely as a consequence of using peer-to-peer transmission
to receive a copy likewise does not require acceptance.  However,
nothing other than this License grants you permission to propagate or
modify any covered work.  These actions infringe copyright if you do
not accept this License.  Therefore, by modifying or propagating a
covered work, you indicate your acceptance of this License to do so.

  10. Automatic Licensing of Downstream Recipients.

  Each time you convey a covered work, the recipient automatically
receives a license from the original licensors, to run, modify and
propagate that work, subject to this License.  You are not responsible
for enforcing compliance by third parties with this License.

  An "entity transaction" is a transaction transferring control of an
organization, or substantially all assets of one, or subdividing an
organization, or merging organizations.  If propagation of a covered
work results from an entity transaction, each party to that
transaction who receives a copy of the work also receives whatever
licenses to the work the party\'s predecessor in interest had or could
give under the previous paragraph, plus a right to possession of the
Corresponding Source of the work from the predecessor in interest, if
the predecessor has it or can get it with reasonable efforts.

  You may not impose any further restrictions on the exercise of the
rights granted or affirmed under this License.  For example, you may
not impose a license fee, royalty, or other charge for exercise of
rights granted under this License, and you may not initiate litigation
(including a cross-claim or counterclaim in a lawsuit) alleging that
any patent claim is infringed by making, using, selling, offering for
sale, or importing the Program or any portion of it.

  11. Patents.

  A "contributor" is a copyright holder who authorizes use under this
License of the Program or a work on which the Program is based.  The
work thus licensed is called the contributor\'s "contributor version".

  A contributor\'s "essential patent claims" are all patent claims
owned or controlled by the contributor, whether already acquired or
hereafter acquired, that would be infringed by some manner, permitted
by this License, of making, using, or selling its contributor version,
but do not include claims that would be infringed only as a
consequence of further modification of the contributor version.  For
purposes of this definition, "control" includes the right to grant
patent sublicenses in a manner consistent with the requirements of
this License.

  Each contributor grants you a non-exclusive, worldwide, royalty-free
patent license under the contributor\'s essential patent claims, to
make, use, sell, offer for sale, import and otherwise run, modify and
propagate the contents of its contributor version.

  In the following three paragraphs, a "patent license" is any express
agreement or commitment, however denominated, not to enforce a patent
(such as an express permission to practice a patent or covenant not to
sue for patent infringement).  To "grant" such a patent license to a
party means to make such an agreement or commitment not to enforce a
patent against the party.

  If you convey a covered work, knowingly relying on a patent license,
and the Corresponding Source of the work is not available for anyone
to copy, free of charge and under the terms of this License, through a
publicly available network server or other readily accessible means,
then you must either (1) cause the Corresponding Source to be so
available, or (2) arrange to deprive yourself of the benefit of the
patent license for this particular work, or (3) arrange, in a manner
consistent with the requirements of this License, to extend the patent
license to downstream recipients.  "Knowingly relying" means you have
actual knowledge that, but for the patent license, your conveying the
covered work in a country, or your recipient\'s use of the covered work
in a country, would infringe one or more identifiable patents in that
country that you have reason to believe are valid.

  If, pursuant to or in connection with a single transaction or
arrangement, you convey, or propagate by procuring conveyance of, a
covered work, and grant a patent license to some of the parties
receiving the covered work authorizing them to use, propagate, modify
or convey a specific copy of the covered work, then the patent license
you grant is automatically extended to all recipients of the covered
work and works based on it.

  A patent license is "discriminatory" if it does not include within
the scope of its coverage, prohibits the exercise of, or is
conditioned on the non-exercise of one or more of the rights that are
specifically granted under this License.  You may not convey a covered
work if you are a party to an arrangement with a third party that is
in the business of distributing software, under which you make payment
to the third party based on the extent of your activity of conveying
the work, and under which the third party grants, to any of the
parties who would receive the covered work from you, a discriminatory
patent license (a) in connection with copies of the covered work
conveyed by you (or copies made from those copies), or (b) primarily
for and in connection with specific products or compilations that
contain the covered work, unless you entered into that arrangement,
or that patent license was granted, prior to 28 March 2007.

  Nothing in this License shall be construed as excluding or limiting
any implied license or other defenses to infringement that may
otherwise be available to you under applicable patent law.

  12. No Surrender of Others\' Freedom.

  If conditions are imposed on you (whether by court order, agreement or
otherwise) that contradict the conditions of this License, they do not
excuse you from the conditions of this License.  If you cannot convey a
covered work so as to satisfy simultaneously your obligations under this
License and any other pertinent obligations, then as a consequence you may
not convey it at all.  For example, if you agree to terms that obligate you
to collect a royalty for further conveying from those to whom you convey
the Program, the only way you could satisfy both those terms and this
License would be to refrain entirely from conveying the Program.

  13. Use with the GNU Affero General Public License.

  Notwithstanding any other provision of this License, you have
permission to link or combine any covered work with a work licensed
under version 3 of the GNU Affero General Public License into a single
combined work, and to convey the resulting work.  The terms of this
License will continue to apply to the part which is the covered work,
but the special requirements of the GNU Affero General Public License,
section 13, concerning interaction through a network will apply to the
combination as such.

  14. Revised Versions of this License.

  The Free Software Foundation may publish revised and/or new versions of
the GNU General Public License from time to time.  Such new versions will
be similar in spirit to the present version, but may differ in detail to
address new problems or concerns.

  Each version is given a distinguishing version number.  If the
Program specifies that a certain numbered version of the GNU General
Public License "or any later version" applies to it, you have the
option of following the terms and conditions either of that numbered
version or of any later version published by the Free Software
Foundation.  If the Program does not specify a version number of the
GNU General Public License, you may choose any version ever published
by the Free Software Foundation.

  If the Program specifies that a proxy can decide which future
versions of the GNU General Public License can be used, that proxy\'s
public statement of acceptance of a version permanently authorizes you
to choose that version for the Program.

  Later license versions may give you additional or different
permissions.  However, no additional obligations are imposed on any
author or copyright holder as a result of your choosing to follow a
later version.

  15. Disclaimer of Warranty.

  THERE IS NO WARRANTY FOR THE PROGRAM, TO THE EXTENT PERMITTED BY
APPLICABLE LAW.  EXCEPT WHEN OTHERWISE STATED IN WRITING THE COPYRIGHT
HOLDERS AND/OR OTHER PARTIES PROVIDE THE PROGRAM "AS IS" WITHOUT WARRANTY
OF ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING, BUT NOT LIMITED TO,
THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
PURPOSE.  THE ENTIRE RISK AS TO THE QUALITY AND PERFORMANCE OF THE PROGRAM
IS WITH YOU.  SHOULD THE PROGRAM PROVE DEFECTIVE, YOU ASSUME THE COST OF
ALL NECESSARY SERVICING, REPAIR OR CORRECTION.

  16. Limitation of Liability.

  IN NO EVENT UNLESS REQUIRED BY APPLICABLE LAW OR AGREED TO IN WRITING
WILL ANY COPYRIGHT HOLDER, OR ANY OTHER PARTY WHO MODIFIES AND/OR CONVEYS
THE PROGRAM AS PERMITTED ABOVE, BE LIABLE TO YOU FOR DAMAGES, INCLUDING ANY
GENERAL, SPECIAL, INCIDENTAL OR CONSEQUENTIAL DAMAGES ARISING OUT OF THE
USE OR INABILITY TO USE THE PROGRAM (INCLUDING BUT NOT LIMITED TO LOSS OF
DATA OR DATA BEING RENDERED INACCURATE OR LOSSES SUSTAINED BY YOU OR THIRD
PARTIES OR A FAILURE OF THE PROGRAM TO OPERATE WITH ANY OTHER PROGRAMS),
EVEN IF SUCH HOLDER OR OTHER PARTY HAS BEEN ADVISED OF THE POSSIBILITY OF
SUCH DAMAGES.

  17. Interpretation of Sections 15 and 16.

  If the disclaimer of warranty and limitation of liability provided
above cannot be given local legal effect according to their terms,
reviewing courts shall apply local law that most closely approximates
an absolute waiver of all civil liability in connection with the
Program, unless a warranty or assumption of liability accompanies a
copy of the Program in return for a fee.

                     END OF TERMS AND CONDITIONS';

	print "\n\n";
	die;
}







#########################################################################################
####################################### PACKAGES ########################################
#########################################################################################










package ListenObject;
sub new	{
	use POSIX ":sys_wait_h";
	my $class = shift;
	my %arg = @_;

	my $report_filename = $arg{ReportFilename};
	my $transport_protocol = $arg{TransportProtocol};
	print "\n*****************\n ListenObject(1st debug): \n **** TRANSPORT PROTO:$transport_protocol ******";
	print "\n";
	##sleep 5;
	my $wait_input = $arg{WaitInput};
	my $protocol = $arg{Protocol};
	my $count_ports;
	my @port_array;
	if (defined $arg{PortArrayRef})	{
		my $port_array_ref = $arg{PortArrayRef};
		until ($count_ports == @$port_array_ref)	{
			@port_array[$count_ports] = $port_array_ref->[$count_ports];
			print "\n count_ports:$count_ports ports:@port_array";
			$count_ports++;
		}
	}

	my $use_default_protocol = $arg{UseDefaultProtocol};
	my $whois_scan = $arg{WhoisScan};
	my $nmap_scan = $arg{NmapScan};
	my $nmap_whois_report = $arg{NmapWhoisReport};
	my $noloop = $arg{NoLoop};
	my $blocking = $arg{Blocking};
	my $recv_buffer = $arg{RecvBuffer};
	my $timeout = $arg{Timeout};
	my $max_requests_per_server = $arg{MaxRequestsPerServer};
	my $saved_transport_protocol = $arg{SavedTransportProtocol};
	my $all_defaults = $arg{AllDefaults};
	my $transblank = $arg{Transblank};


	################# INTERNAL VARIABLES ################

	my $is_default_ports;	# Necessary?

	my @imap_port_array = (143, 993);
	my @ftp_port_array = (20, 21, 69, 115, 152);
	my @telnet_port_array = (23, 107, 123, 992, 12323, 2323,2345, 9999);
	my @smtp_port_array = (25, 465, 587, 2525, 2526);
	my @http_port_array = (80, 8080, 81);
	my @pop3_port_array = (110, 995);
	my @tr69_port_array = 7547;
	my @bgp_port_array = 179,1024,1025;
	my @bittime_port_array = (37,123);
	my @asciitime_port_array = 13;
	my @systat_port_array = 11;
	my @echo_port_array = 7;
	my @default_port_array = (@imap_port_array,
							@ftp_port_array,
							@telnet_port_array,
							@smtp_port_array,
							@http_port_array,
							@pop3_port_array,
							@tr69_port_array,
							@bgp_port_array,
							@asciitime_port_array,
							@systat_port_array,
							@echo_port_array
							);



	my $csv_report;





# IFF no ports OR protocols are given, listen on a default set of ports with a default set of protos

	print "\n****************ListenObject:*****************";
	print "\n **** use_default_protocol: $use_default_protocol ****************\n";
	print "\n";
	#sleep 1;



	if (!@port_array && !$protocol)	{
		print "\n No protocol or ports defined, selecting defaults...";
		@port_array = @default_port_array;
		$use_default_protocol = "YES";		# Implied by an undefined protocol
		}

# IFF port(s) are given, AND no protocol is given, use default protocols for those ports
#	otherwise select a generic protocol - something like a banner with blank outputs

	elsif (@port_array && !$protocol)  {	# think this is the transblank bug fixed

		print "\n Protocol NOT selected. Will use defaults for selected ports";
		print "\n *** ListenObject BUG***\n ** transport_protocol:$transport_protocol ***";
		print "\n";
		#sleep 1;
		$use_default_protocol = "YES";			# Again, this is implied by an undefined protocol
	}

# IFF no server port is given, AND a protocol is given, listen on trad ports for that proto

	elsif (!@port_array && $protocol)	{

		if ($protocol eq "imap") 	{
			print "selecting IMAP ports";
			@port_array = @imap_port_array;
		}
		elsif ($protocol eq "ftp") 	{
			print "selecting FTP ports";
			@port_array = @ftp_port_array;
		}
		elsif ($protocol eq "telnet"){
			print "Selecting telnet ports";
			@port_array = @telnet_port_array;
		}
		elsif ($protocol eq "smtp")	{
			print "Selecting SMTP ports";
			@port_array = @smtp_port_array;
		}
		elsif ($protocol eq "http")	{
			print "Selecting HTTP ports";
			@port_array = @http_port_array;
		}
		elsif ($protocol eq "pop3")	{
			print "Selecting POP3 ports";
			@port_array = @pop3_port_array;
		}
		elsif ($protocol eq "tr-69"){
			print "Selecting TR-69 ports";
			@port_array = @tr69_port_array;
		}
		elsif ($protocol eq "bgp"){
			print "Selecting BGP ports";
			@port_array = @bgp_port_array;
		}
		elsif ($protocol eq "asciitime")	{
			print "Selecting ASCII time port.";
			@port_array = @asciitime_port_array;
			if (!defined $transport_protocol)	{$transport_protocol = "udp"}
		}
		elsif ($protocol eq "hacktime-2036" ||
				$protocol eq "hacktime-1900"
				)	{
			print "Selecting hacktime ports";
			@port_array = @bittime_port_array;
			if (!defined $transport_protocol)	{$transport_protocol = "udp"}
		}
		elsif ($protocol eq "systat")	{
			print "Selecting systat ports";
			@port_array = @systat_port_array;
			if (!defined $transport_protocol)	{$transport_protocol = "udp"}
		}
		elsif ($protocol eq "echo")	{
			print "Selecting echo ports";
			@port_array = @echo_port_array;
			if (!defined $transport_protocol)	{$transport_protocol = "udp"}
			}
		else	{
			print "\n ERROR! You have selected a protocol that does not have default ports";
			print "\n associated with it. Supported protocols are IMAP, FTP, Telnet, SMTP, HTTP, ";
			print "\n POP3, TR-69 and BGP. Please use lower case, ie 'bgp', not 'BGP'.";
			print "\n\n\n";
			die;
		}
	}
	
	#print "\n\n\n\n";
	#print "Max requests per server:$max_requests_per_server";
	#print "\n\n";
	#die "debugging";

	print "\n****************ListenObject:*****************";
	print "\n **** use_default_protocol: $use_default_protocol ****************\n";
	print "\n";
	#sleep 1;

	### If both are defined, nothing has to be done, so we go ahead with the listener routine.

	print "\n";
	$csv_report = $report_filename;
	chop $csv_report;
	chop $csv_report;
	chop $csv_report;
	chop $csv_report;
	$csv_report .= "-table.csv";
	WriteReportFile ("\nPID,client_IP,client_port,server_port,trans_proto,time", $csv_report);

	$count_ports = 0;

	print "\n*****************\n ListenObject(2nd debug): \n **** TRANSPORT PROTO:$transport_protocol ******";
	print "\n**** use_default_protocol:$use_default_protocol ****\n";
	print "\n";
	##sleep 5;
	# Reverse lookup protocol from ports #
	# (Matches ports / protocols to their transport protocols)

	#### THIS MODULE DETECTS AND ACTIVATES VARIOUS DEFAULT MODES ####



	if (!defined $protocol)	{print "*** I'M DETECTING PROTOCOL NON-DEFINE, MOFO! ****";}
	if ($use_default_protocol eq "YES")	 {print "\n *** USE DEFAULT PROTOCOL DETECTED***";}
	if ($transport_protocol ne 'udp')	{
		print "\n ***transport protocol NOT udp! ***";
		print "\n ** Therefore, it MUST BE tcp - setting...";
		$transport_protocol = "tcp";
		print "\n * transport_protocol set to $transport_protocol! (fixes nonblocking bug) *";
	}
	until ($count_ports == scalar(@port_array))	{
		if (defined ($saved_transport_protocol))	{			# solves nonblocking bug
			$transport_protocol = $saved_transport_protocol;
		}
		if (!defined $protocol || $use_default_protocol eq "YES" )	{
			#sleep 1;
			print "\n";
			print "\n *******************************************************";
			print "\n *                                                     *";
			print "\n * TRANSPORT PROTOCOL:$transport_protocol*";
			print "\n * use_default_protocol:$use_default_protocol*";
			print "\n * protocol:$protocol*";
			print "\n * port_array[$count_ports]:$port_array[$count_ports]*";
			print "\n *******************************************************";
			print "\n";
			#sleep 3;
			print "\n";

			if ((grep {$_ eq $port_array[$count_ports]} (@imap_port_array)) &&
			($transport_protocol eq "tcp"))	{
#				sleep 1;
				print "\n ****** IMAP PROTOCOL AUTO-SELECTED! ******";
				print "\n ****** IMAP PROTOCOL AUTO-SELECTED! ******";
				print "\n ****** IMAP PROTOCOL AUTO-SELECTED! ******";
				print "\n ****** IMAP PROTOCOL AUTO-SELECTED! ******";
				print "\n ****** IMAP PROTOCOL AUTO-SELECTED!  Port $port_array[$count_ports]******";
#				sleep 1;
				$protocol = "imap";
			}
			elsif ((grep {$_ eq $port_array[$count_ports]} (@ftp_port_array)) &&
			($transport_protocol eq "tcp"))	{
#				sleep 1;
				print "\n ****** FTP PROTOCOL AUTO-SELECTED! ******";
				print "\n ****** FTP PROTOCOL AUTO-SELECTED! ******";
				print "\n ****** FTP PROTOCOL AUTO-SELECTED! ******";
				print "\n ****** FTP PROTOCOL AUTO-SELECTED! ******";
				print "\n ****** FTP PROTOCOL AUTO-SELECTED! ******";
				print "\n ****** FTP PROTOCOL AUTO-SELECTED! Port $port_array[$count_ports] ******";
#				sleep 1;
				$protocol = "ftp";
			}
			elsif ((grep {$_ eq $port_array[$count_ports]} (@telnet_port_array)) &&
			($transport_protocol eq "tcp"))	{

				#sleep 1;
				print "\n ******* TELNET PROTOCOL AUTO-SELECTED! ***********";
				print "\n ******* TELNET PROTOCOL AUTO-SELECTED! ***********";
				print "\n ******* TELNET PROTOCOL AUTO-SELECTED! ***********";
				print "\n ******* TELNET PROTOCOL AUTO-SELECTED! ***********";
				print "\n ******* TELNET PROTOCOL AUTO-SELECTED! ***********";
				print "\n ******* TELNET PROTOCOL AUTO-SELECTED!  Port $port_array[$count_ports]***********";
				#sleep 5;
				$protocol = "telnet";
			}

			elsif ((grep {$_ eq $port_array[$count_ports]} (@smtp_port_array)) &&
			($transport_protocol eq "tcp"))	{
				#sleep 1;
				print "\n ********** SMTP PROTOCOL AUTO-SELECTED! **********";
				print "\n ********** SMTP PROTOCOL AUTO-SELECTED! **********";
				print "\n ********** SMTP PROTOCOL AUTO-SELECTED! **********";
				print "\n ********** SMTP PROTOCOL AUTO-SELECTED! **********";
				print "\n ********** SMTP PROTOCOL AUTO-SELECTED! **********";
				print "\n ********** SMTP PROTOCOL AUTO-SELECTED! **********";
				#sleep 1;
				$protocol = "smtp";
			}
			elsif ((grep {$_ eq $port_array[$count_ports]} (@http_port_array)) &&
			($transport_protocol eq "tcp"))	{
				#sleep 1;
				print "\n *********** HTTP PROTOCOL AUTO-SELECTED! ******";
				print "\n *********** HTTP PROTOCOL AUTO-SELECTED! ******";
				print "\n *********** HTTP PROTOCOL AUTO-SELECTED! ******";
				print "\n *********** HTTP PROTOCOL AUTO-SELECTED! ******";
				print "\n *********** HTTP PROTOCOL AUTO-SELECTED!  Port $port_array[$count_ports]******";
				#sleep 1;
				$protocol = "http";

			}

			elsif ((grep {$_ eq $port_array[$count_ports]} (@pop3_port_array)) &&
			($transport_protocol eq "tcp"))	{
				#sleep 1;
				print "\n ***** POP3 PROTOCOL AUTO-SELECTED! *********";
				print "\n ***** POP3 PROTOCOL AUTO-SELECTED! *********";
				print "\n ***** POP3 PROTOCOL AUTO-SELECTED! *********";
				print "\n ***** POP3 PROTOCOL AUTO-SELECTED! *********";
				print "\n ***** POP3 PROTOCOL AUTO-SELECTED!  Port $port_array[$count_ports] *********";
				#sleep 1;
				$protocol = "pop3";
			}
			elsif ((grep {$_ eq $port_array[$count_ports]} (@tr69_port_array)) &&
			($transport_protocol eq "tcp"))	{
				#sleep 1;
				print "\n ****** TR69 PROTOCOL AUTO-SELECTED! *********** ";
				print "\n ****** TR69 PROTOCOL AUTO-SELECTED! *********** ";
				print "\n ****** TR69 PROTOCOL AUTO-SELECTED! *********** ";
				print "\n ****** TR69 PROTOCOL AUTO-SELECTED! *********** ";
				print "\n ****** TR69 PROTOCOL AUTO-SELECTED!  Port $port_array[$count_ports]*********** ";
				#sleep 1;
				$protocol = "tr-69"; # NOT "tr69"
			}

			elsif ((grep {$_ eq $port_array[$count_ports]} (@bgp_port_array)) &&
			($transport_protocol eq "tcp"))	{
				#sleep 1;
				print "\n ****** BGP PROTOCOL AUTO-SELECTED! *********** ";
				print "\n ****** BGP PROTOCOL AUTO-SELECTED! *********** ";
				print "\n ****** BGP PROTOCOL AUTO-SELECTED! *********** ";
				print "\n ****** BGP PROTOCOL AUTO-SELECTED! *********** ";
				print "\n ****** BGP PROTOCOL AUTO-SELECTED! Port $port_array[$count_ports] *********** ";
				#sleep 1;

				$protocol = "bgp";
			}


			######################## this is the UDP detection bit ###############

			elsif ((grep {$_ eq $port_array[$count_ports]} (@asciitime_port_array)) &&
			($transport_protocol eq "udp"))	{
			#if (grep {$_ eq $port_array[$count_ports]} (@asciitime_port_array)){
				#sleep 1;
				print "\n ****** ASCIITIME PROTOCOL AUTO-SELECTED! *********** ";
				print "\n ****** ASCIITIME PROTOCOL AUTO-SELECTED! *********** ";
				print "\n ****** ASCIITIME PROTOCOL AUTO-SELECTED! *********** ";
				print "\n ****** ASCIITIME PROTOCOL AUTO-SELECTED! *********** ";
				print "\n ****** ASCIITIME PROTOCOL AUTO-SELECTED! Port $port_array[$count_ports] *********** ";
				#sleep 1;
				$protocol = "asciitime";
			}
			elsif ((grep {$_ eq $port_array[$count_ports]} (@bittime_port_array)) &&
			($transport_protocol eq "udp"))	{
				#sleep 1;
				print "\n  ** BITTIME / HACKTIME PROTOCOL AUTO-SELECTED! ** ";
				print "\n  ** BITTIME / HACKTIME PROTOCOL AUTO-SELECTED! ** ";
				print "\n  ** BITTIME / HACKTIME PROTOCOL AUTO-SELECTED! ** ";
				print "\n  ** BITTIME / HACKTIME PROTOCOL AUTO-SELECTED! Port $port_array[$count_ports] ** ";
				print "\n";
				#sleep 1;
				$protocol = "bittime";
			}
			elsif ((grep {$_ eq $port_array[$count_ports]} (@systat_port_array)) &&
			($transport_protocol eq "udp"))	{
				#sleep 1;
				print "\n  ** SYSTAT PROTOCOL AUTO-SELECTED! ** ";
				print "\n  ** SYSTAT PROTOCOL AUTO-SELECTED! ** ";
				print "\n  ** SYSTAT PROTOCOL AUTO-SELECTED! ** ";
				print "\n  ** SYSTAT PROTOCOL AUTO-SELECTED! ** ";
				print "\n  ** SYSTAT PROTOCOL AUTO-SELECTED! Port $port_array[$count_ports] ** ";
				print "\n";
				#sleep 1;
				$protocol = "systat";
			}
			elsif ((grep {$_ eq $port_array[$count_ports]} (@echo_port_array)) &&
			($transport_protocol eq "udp"))	{
				#sleep 1;
				print "\n  ** ECHO PROTOCOL AUTO-SELECTED! ** ";
				print "\n  ** ECHO PROTOCOL AUTO-SELECTED! ** ";
				print "\n  ** ECHO PROTOCOL AUTO-SELECTED! ** ";
				print "\n  ** ECHO PROTOCOL AUTO-SELECTED! Port $port_array[$count_ports] ** ";
				print "\n";
				#sleep 1;
				$protocol = "echo";
			}



			elsif ($transport_protocol eq "udp" &&
			$use_default_protocol eq "YES" &&
			$all_defaults eq "YES" )	{
				#sleep 1;
				print "adding 1 to count_ports... $count_ports + ";
				$count_ports++;
				print "1 = $count_ports...";
				print "\n   *** Nexting.... *** ";
				print "\n   *** Nexting.... *** ";
				print "\n   *** Nexting.... *** ";
				#sleep 1;
				next;
			}


			else  {
				$protocol = "transblank";
			}
		}
		print "\n*****************\n ListenObject(3rd debug): \n **** TRANSPORT PROTO:$transport_protocol ******";
		print "\n";

		print "\n Spooling through port array. Current port is: @port_array[$count_ports]";
		#print "\n*************** DEBUGGING **************** \n  Dollarex (Error):$!
		# looptimes:$looptimes \n max_requests_per_server: $max_requests_per_server
		# protocol: $protocol \n blocking:$blocking \n **********************************************\n";

		my $listener = {
			Port => @port_array[$count_ports],
			Protocol => $protocol,
			Blocking => $blocking,
			RecvBuffer => $recv_buffer,
			NoLoop => $noloop,
			Timeout => $timeout,
			TransportProtocol => $transport_protocol,
			MaxRequestsPerServer => $max_requests_per_server,
			WhoisScan => $whois_scan,
			NmapScan => $nmap_scan,
			ReportFilename => $report_filename,
			CsvReport => $csv_report,
			WaitInput => $wait_input,
			Transblank => $transblank
		};
		bless $listener, $class;
		$listener->Listen();
		$count_ports++;
	}

}


#############################################################################################

sub Listen	{

	use Socket;
	use Fcntl qw/:DEFAULT :flock/;

	my $arg = shift;

	if ($arg->{Port} eq undef)	{
		print "\n Port not defined. Listen requires that you pass a Port variable to it.\n ";
		return;
	}
	my $server_port = $arg->{Port};

	my $protocol = $arg->{Protocol};
	if ($protocol eq undef)	{
		print "\n Protocol not defined. Selecting a default - will send blank output to clients.\n";
		$protocol = "transblank";
	}

	my $blocking = $arg->{Blocking};
	if ($blocking eq undef)	{				# if (!blocking) trips if it's set to 0 or undefined.
		print "Blocking param not sent! Setting to default value which is BLOCKING MODE ON \n";
		$blocking = 1;
	}

	my $recv_buffer = $arg->{RecvBuffer};
	if ($recv_buffer eq undef)	{
		$recv_buffer = 1024;
	}

	my $noloop = $arg->{NoLoop};
	print "\n\n\t \t\t ****** NOLOOP IS $noloop ******";
	print "\n\n";
	
	my $timeout = $arg->{Timeout};


	my $transport_protocol = $arg->{TransportProtocol};
	if ($transport_protocol eq undef)	{
		print "\n************************\n **** TRANSPORT PROTO UNDEFINED, CHOOSING TCP BY DEFAULT ******";
		print "\n";
		#sleep 5;
		$transport_protocol = "tcp"
	}
	print "\n";
	print "\n**** TRANSPORT PROTO:$transport_protocol ******";
	print "\n";
	#sleep 5;

	my $multiplexing;
	my $max_requests_per_server = $arg->{MaxRequestsPerServer};
	
	######## THIS LOOKS A BIT DODGY! #########
	if ($max_requests_per_server eq undef)	{
		$multiplexing = "OFF";
	}
	else {
		$multiplexing = "ON";
	}

	my $whois_scan = $arg->{WhoisScan};
	my $nmap_scan = $arg->{NmapScan};
	my $report_filename = $arg->{ReportFilename};
	my $wait_input = $arg->{WaitInput};
	my $transblank = $arg->{Transblank};

	my $procid;
	my $grandchild_pid;
	my $forktimes = 0;
	my $temp_report_filename;


	my @server_conversation;
	my $server_prompt;
	my $conversation_length = 1;

	my @bannerblank_conversation;
	my $bannerblank_prompt;
	my $bannerblank;

	my @telnet_conversation = ("Username:", "Password:", "Login successful.\nComputer:~\$ ");
	my $telnet_prompt = "Computer:~\$ ";

	my @transblank_conversation = chr(13), chr(13);
	my @fuzz_conversation;
	my $fuzz;

	my @imap_conversation = ("+OK IMAP4 service ready", "+OK LOGIN completed", "+OK LOGIN completed", " OK ");
	my $imap_prompt = " OK ";

	my @ftp_conversation = ("220 FTP-Server\r\n", "331 OK enter PASS command\r\n", "220 Logged in\r\n");
	my $ftp_prompt = "200 OK\r\n";

	my @smtp_conversation = ("220 SMTP-Server\r\n", "220 OK\r\n", "220 OK\r\n");
	my $smtp_prompt = "220 OK\r\n";

	my @pop3_conversation = ("+OK POP3-Server\r\n", "+OK Password required\r\n", "+OK Logged in\r\n");
	my $pop3_prompt = "+OK";
	my $email_prompt = "200 OK\r\n";

	my $http_temp;
	my $http_length;
	my $http_prompt;
	my @http_conversation = (" ");

	if (-e "webpage.html")	{
		open WEBPAGE, "webpage.html" or die "\n\nReality failure error. Couldn't open webpage.html.\n\n";
		while (<WEBPAGE>)	{
			$http_temp .= $_;
		}
		$http_length = length($http_temp);
		print "\n \t **************\n \t http_length:$http_length \n \t *********************\n";		
		$http_prompt = ("HTTP/1.1 200 OK
Date: Sat, 07 Oct 2017 18:43:18 GMT
Server: Apache/2.4.18 (Ubuntu)
Content-Length: $http_length
Connection: close
Content-Type: text/html; charset=iso-8859-1

<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">$http_temp
");		
		$http_length += length($http_prompt);

		print "\n \t **************\n \t http_length:$http_length \n \t *********************\n";
		$http_prompt = ("HTTP/1.1 200 OK
Date: Sat, 07 Oct 2017 18:43:18 GMT
Server: Apache/2.4.18 (Ubuntu)
Content-Length: $http_length
Connection: close
Content-Type: text/html; charset=iso-8859-1

<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">$http_temp
");		



	}
	else	{
		$http_prompt = ('HTTP/1.1 200 OK
Date: Sat, 07 Oct 2017 18:43:18 GMT
Server: Apache/2.4.18 (Ubuntu)
Content-Length: 301
Connection: close
Content-Type: text/html; charset=iso-8859-1

<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>404 Not Found</title>
</head><body>
<h1>Not Found</h1>
<p>The resource you requested could not be loaded.<br />
</p>
<hr>
<address>Apache/2.4.18 (Ubuntu) Server </address>
</body></html>');
	}


	@http_conversation[0] = $http_prompt;
	$http_prompt = "HTTP/1.1 200 OK\n";
	my @tr69_conversation = ('HTTP/1.1 401 Unauthorized ',
						 'HTTP/1.1 HTTP/1.1 200 OK',
						 'HTTP/1.1 404 Not Found');
	my $tr69_prompt = 'HTTP/1.1 HTTP/1.1 200 OK';

	my @bgp_conversation = (chr(255).chr(255).chr(255).chr(255).chr(255).chr(255).chr(255).chr(255).chr(255).chr(255).chr(255).chr(255).chr(255).chr(255).chr(255).chr(255).chr(0).chr(29).chr(01).chr(04).chr(254).chr(9).chr(0).chr(180).chr(192).chr(168).chr(0).chr(1).chr(0)),
						 (chr(255).chr(255).chr(255).chr(255).chr(255).chr(255).chr(255).chr(255).chr(255).chr(255).chr(255).chr(255).chr(255).chr(255).chr(255).chr(255).chr(0).chr(19).chr(4));
	my $bgp_prompt = (chr(255).chr(255).chr(255).chr(255).chr(255).chr(255).chr(255).chr(255).chr(255).chr(255).chr(255).chr(255).chr(255).chr(255).chr(255).chr(255).chr(0).chr(19).chr(4));


	my $timestamp;

	my $temp;
	my $count;
	my $count_conversation;


#	 ADDENDA for socket version
#	 (You are in Listen () )
	my $my_addr;
	# my $raw_client_ip_and_port;
	# my $raw_client_ip;
	# my $connect_test;
	# my $looptest;
	# my $side;
	# my $data;
	my $shell;
	my $csv_report = $arg->{CsvReport};


	# moved from "Create UDP server" block
	my $udp_client_data;
	my $process_id;
	my $data;
	my $side;
	my $bytes_sent;
	my $buffer;
	my $shit;

	my $addr;
	my $client_port;
	my $raw_client_ip;
	my $raw_client_ip_and_port;
	my $client_ip;
	my $input;
	my $fuzz_prompt;
	my $max_fuzz_len;
	my $non_printing_found;
	my $waitresult;



	#print "\n\n\n\n Listener!\n";
	#print "Max requests per server:$max_requests_per_server";
	#print "\n\n";
	#die "debugging";

		### Set up conversation ###

	if ($protocol eq "imap") 	{
		@server_conversation = @imap_conversation;
		$server_prompt = $imap_prompt;
		$conversation_length = 2;
	}

	elsif ($protocol eq "ftp") 	{
		@server_conversation = @ftp_conversation;
		$server_prompt = $ftp_prompt;
		$conversation_length = 2;
	}

	elsif ($protocol eq "telnet")	{
		@server_conversation = @telnet_conversation;
		$server_prompt = $telnet_prompt;
		$conversation_length = 2;
	}

	elsif ($protocol eq "smtp")	{
		@server_conversation = @smtp_conversation;
		$server_prompt = $smtp_prompt;
	}

	elsif ($protocol eq "http")	{
		@server_conversation = @http_conversation;
		$server_prompt = $http_prompt;
		$conversation_length = 0;
	}

	elsif ($protocol eq "pop3")	{
		@server_conversation = @pop3_conversation;
		$server_prompt = $pop3_prompt;
		$conversation_length = 2;
	}

	elsif ($protocol eq "tr-69")	{
		@server_conversation = @tr69_conversation;
		$server_prompt = $tr69_prompt;
		$conversation_length = 2;
	}
	elsif ($protocol eq "bgp")	{
		@server_conversation = @bgp_conversation;
		$server_prompt = $bgp_prompt;
		$conversation_length = 1;
	}

	elsif ($protocol eq "fuzz")	{
		print "\n -proto:fuzz option selected. Will try to confound the enemy with random garbage!";
		$fuzz = "ON";
		undef @server_conversation;
	}

	elsif ($protocol eq "transblank" || $transblank eq "ON")	{
		print "\n -proto:transblank option selected. Will send blank responses to the enemy.";
		$transblank = "ON";
		@server_conversation = @transblank_conversation;
		$server_prompt = $transblank_conversation[0];
		$conversation_length = 0;
	}
		#### UDP PROTOCOL STUFF ####
	elsif ($protocol eq "asciitime")	{
		print "\n -proto:asciitime option selected. Will send time in ASCII format (Port 13 UDP)";
		@server_conversation = "\n ".localtime()." \n";
		$server_prompt = "\n ".localtime()." \n";
		$conversation_length = 0;
	}

	##  I've decided not to emulate this type of server, so this code is obsolete.

#	elsif ($protocol eq "bittime")	{
#		print "\n -proto:bittime option selected. Will send time in bit format (Ports 37,123 UDP)";
#		$temp = time();
#		$count = 0;
#		until ($count == length ($temp))	{
#			$server_prompt .= chr(substr ($temp, $count, 1));
#			$server_conversation[0] .= chr(substr ($temp, $count, 1));
#			$count++;
#			print "\n temp:$temp count:$count";
#		}
#		#@server_conversation = $server_prompt;
#		$conversation_length = 0;
#		## May need adjustment. DEFINITELY needs research to confirm it's supposed to output this##
#	}
	elsif ($protocol eq "hacktime-2036")	{
		print "\n -proto:hacktime-2036 selected. Will send a load of FFs as time signal";
		$server_prompt = chr(255).chr(255).chr(255).chr(255).chr(255).chr(255).chr(255).chr(255).chr(255).chr(255).chr(255).chr(255).chr(255).chr(255).chr(255).chr(255).chr(255).chr(255).chr(255).chr(255).chr(255).chr(255).chr(255).chr(255).chr(255).chr(255).chr(255).chr(255).chr(255).chr(255).chr(255).chr(255).chr(255).chr(255).chr(255).chr(255).chr(255).chr(255).chr(255).chr(255).chr(255).chr(255).chr(255).chr(255).chr(255).chr(255).chr(255).chr(255);
		if ($server_port == 37)	{
			$server_prompt = chr(255).chr(255).chr(255).chr(255);
		}
		@server_conversation = $server_prompt;
		$conversation_length = 0;
	}
	elsif ($protocol eq "hacktime-1900")	{
		print "\n -proto:hacktime-1900 selected. Will send 00s as time signal";
		$server_prompt = chr(1).chr(1).chr(1).chr(1).chr(1).chr(1).chr(1).chr(1).chr(1).chr(1).chr(1).chr(1).chr(1).chr(1).chr(1).chr(1).chr(1).chr(1).chr(1).chr(1).chr(1).chr(1).chr(1).chr(1).chr(1).chr(1).chr(1).chr(1).chr(1).chr(1).chr(1).chr(1).chr(1).chr(1).chr(1).chr(1).chr(1).chr(1).chr(1).chr(1).chr(1).chr(1).chr(1).chr(1).chr(1).chr(1).chr(1).chr(1);
		if ($server_port == 37)	{
			$server_prompt = chr(1).chr(1).chr(1).chr(1);
		}
		@server_conversation = $server_prompt;
		$conversation_length = 0;

	}
	elsif ($protocol eq "systat")	{
		print "\n -proto:systat selected. Will send a fake userlist. (Port 11 UDP)";
		$server_prompt = "root \nqueeg \nsupercalifragilistic \n";
		@server_conversation = $server_prompt;
		$conversation_length = 0;
	}

	print "\n**** TRANSPORT PROTO:$transport_protocol ******";
	print "\n";
	#sleep 5;

#	print "server_conversation: @server_conversation";
#	print "\n zero: @server_conversation[0] one:@server_conversation[1] two:@server_conversation[2]";
#	print "\n server_prompt: $server_prompt";
#	print "\n";

	print "\n Just before forking, server_port is $server_port";
	print "\n";
	### FORK IT HERE! ###
	$procid = fork();
	if ($procid)	{
		print "\n Parent process returning from Listen routine...\n";
		return;
	}
	elsif ($procid == 0)	{
		print "\n Just after forking, server_port is $server_port";
#		$count_conversation = 0; # Failed attempt to make it like a TCP server
		$looptimes++;
		while (1)	{						# INFINITE LOOP - use "last" to escape
			print "\n*************** DEBUGGING **************** \n server_port: $server_port \n Dollarex (Error):$! \n looptimes:$looptimes \n server_prompt:$server_prompt \n grandchild_pid:$grandchild_pid  forktimes: $forktimes \n max_requests_per_server: $max_requests_per_server \n protocol: $protocol \n blocking:$blocking\n **********************************************\n";
			$| = 1;							# Autoflush (VERY IMPORTANT VOODOO)
			print "\n About to create a server with port $server_port...";

			##########################################################################
			########################### Create UDP server  ###########################
			##########################################################################

				# N.B. $server_prompt in UDP server is $server_output in TCP server! #
				# (might want to fix that)

			if ($transport_protocol eq 'udp')	{

				socket(SERVER, PF_INET, SOCK_DGRAM, getprotobyname($transport_protocol)	)
				or die "\n\n ** Couldn't create socket on $server_port using $transport_protocol. Error: $! ** \n\n";

				select( ( select(SERVER), $|=1 )[0] ); # Nicked this from the internet,cant remember where

				setsockopt( SERVER, SOL_SOCKET, SO_REUSEADDR, 1 )
				or die "setsockopt SO_REUSEADDR: $!";
				setsockopt( SERVER, SOL_SOCKET, SO_BROADCAST, 1 )
				or die "setsockopt SO_BROADCAST: $!";

				$my_addr = sockaddr_in($server_port, INADDR_ANY);
				unless (bind (SERVER, $my_addr))	{

	# Once, I had a plan to create a spoof NTP server. I decided not to bother, but just
	# in case I bring it back, here's a bit of bodge code left over from it

					#if ($server_port == 123 && $all_defaults )	{
					#	print "\n";
					#	die "\n Ignore this, it's probably just a stupid bug. \n";
					#}
					#else	{
					$verbal_report = "\n ERROR. Couldn't listen on $transport_protocol port $server_port. Syserr:$! (Are we root or already listening on port $server_port ?)";
					print "\n";
					print "************ Writing error message to $report_filename ************ ";
					print "\n";
					WriteReportFile ($verbal_report, $report_filename);
					die "\n\n ** Farts! Couldn't bind to port $server_port: $! (Are we root? Is something already using that port?)** \n\n";
					#}
				}
				print "\n Listening on port $server_port using $transport_protocol protocol  \$!:**$!** \$@:**$@** \$.:**$.** \n";
				while ($transport_protocol eq 'udp')	{
					#### Moved some variable declarations to start of routine
					undef $bytes_sent;
					$process_id = $$;

					print "*** Listening on port $server_port for $transport_protocol connections ***";
					print "\n";
					print "Transblank is $transblank";
					print "\n";
					if ($blocking ==0)	{
						until ($udp_client_data =~ "\n")	{

							if ( ($raw_client_ip_and_port = recv SERVER, $udp_client_data, 4096, MSG_DONTWAIT) )	{
								($client_port, $raw_client_ip) = unpack_sockaddr_in($raw_client_ip_and_port);
								$client_ip = inet_ntoa($raw_client_ip);
								print "ADDR:$client_ip SERVER PORT: $server_port  CLIENT PORT:$client_port \n INPUT:$udp_client_data\n";
								###  Print status. Eagle eyed viewers will notice this is not in ascii. Tough shit.
							}
						}
						undef $udp_client_data;
					}
					else	{
						print "\n ** BLOCKING MODE ** \n\n";
						if( $raw_client_ip_and_port = recv( SERVER, $udp_client_data, 4096, 0 ) ) {
							#print "$raw_client_ip_and_port => $udp_client_data\n";
							($client_port, $raw_client_ip) = unpack_sockaddr_in($raw_client_ip_and_port);
							$client_ip = inet_ntoa($raw_client_ip);
							print "ADDR:$client_ip SERVER PORT: $server_port CLIENT PORT:$client_port \n INPUT:$udp_client_data\n";

						}
					}

					print "\n FINISHED RECV IF / THEN BLOCKS \n";

					$time = localtime();
					$time =~ s/ /-/g; # Strip whitespace so it looks good in a spreadsheet
					$verbal_report = "\n$process_id,$client_ip,$client_port,$server_port,$transport_protocol,$time";
					WriteReportFile($verbal_report,$csv_report);

					$verbal_report = "\n ############## $transport_protocol server: AN EVIL HACKER CONNECTED TO US! #########################\n";
					$verbal_report .= "\n *** ";
					unless ($noloop) {$verbal_report .= "Looptimes:$looptimes ";}
					else {$verbal_report .= " Looping OFF ";}
					$time = localtime;
					$verbal_report .= " *** Time: $time  *** transp.proto:$transport_protocol ";
					$verbal_report .= "\n Them: $client_ip port $client_port";
					$verbal_report .= "\n Us: (our own IP) port $server_port\n\n";
					$side = "Client";
					$data = $udp_client_data;
					$chr_data_report = ProcessChrData($side,$data);
					$verbal_report .= $chr_data_report;
					if ($server_port == 67 || $server_port == 68)	{
						$verbal_report .= "\n Connection likely a DHCP request from a LAN peer \n";
						$verbal_report .= "so not sending anything to $client_ip....";
					}
					$verbal_report .= "\n________________________________________________________________\n";
					WriteReportFile($verbal_report, $report_filename);

					if ($protocol eq "echo")	{
						$server_prompt = $udp_client_data;
					}
					elsif ($protocol eq "asciitime")	{
						$server_prompt = "\n $time \n";
					}

				# Again, no longer supporting this protocol, so code is commented out
#					elsif ($protocol eq "bittime")	{
#						print "\n -proto:bittime option selected. Will send time in bit format (Ports 37,152 UDP)";
#						$temp = time();
#						$count = 0;
#						$server_prompt = "";
#						$server_conversation[0] = "";
#						until ($count == length ($temp))	{
#							$server_prompt .= chr(substr ($temp, $count, 1));
#							$server_conversation[0] .= chr(substr ($temp, $count, 1));
#							$count++;
#							print "\n temp:$temp count:$count";
#						}
#					$conversation_length = 0;
#					}
					elsif ($protocol eq "fuzz")	{
						#unless ($wait_input eq "ON" && $count_conversation == 0)	{
						print STDOUT "\n Rolling some garbage to throw at the enemy...";
						$fuzz_prompt = "";
						#until (length( $fuzz_prompt ) == $fuzzlength)	{
						$max_fuzz_len = int(rand(256));
						print STDOUT "\n Random length of random string will be $max_fuzz_len";
						print STDOUT "\n Characters generated: ";
						until (length( $fuzz_prompt ) == $max_fuzz_len)	{
							$fuzz_prompt .= chr(int(rand(256)));
							print STDOUT length( $fuzz_prompt ).",";
						}
						print STDOUT "\n  Fuzz output generated!\n";
						#print STDOUT "\n  Fuzz output:$fuzz_prompt";
						push @server_conversation, $fuzz_prompt;
						#print "\n  Server_conversation:@server_conversation";
						$server_prompt = $fuzz_prompt;
					}
					elsif ($protocol eq "systat") {
						$server_prompt = $server_conversation[0];
					}
					elsif ($protocol =~ "hacktime")	{
						$server_prompt = $server_conversation[0];
					}
					else	{
						$server_prompt = chr(13);	# Think the lack of server_prompt was problem!
					}

					### Failed attempt to make it act like a TCP server, forget it.
					#else	{
					#	$server_prompt = $server_conversation[$count_conversation];
					#	$count_conversation++;
					#	if ($count_conversation > $conversation_length) {
					#		$server_conversation[$count_conversation] = $server_prompt;
					#	}
					#}

					if ($server_port == 67 || $server_port == 68)	{
						print "\n LIKELY A DHCP REQUEST. SLEEPING IT OFF (5 mins starting ".localtime()."....";
						print "\n";
						sleep 300;
						next;

					}

					print "\n";
					print "Should be sending the following: \n$server_prompt\n";


					my $broadcastAddr = sockaddr_in( 9999, INADDR_BROADCAST );
					print "\n broadcastAddr:$broadcastAddr";
					print "\n raw_client_ip_and_port:$raw_client_ip_and_port";
					print "\n\n\n";
					#die;
					#setsockopt( SOCKET, SOL_SOCKET, SO_BROADCAST, 1 );

					until ($bytes_sent)	{
						if ($blocking == 0)	{
							$bytes_sent = send (SERVER, $server_prompt, MSG_DONTWAIT, $raw_client_ip_and_port);
						}
						else	{
							$bytes_sent = send (SERVER, $server_prompt, 0, $raw_client_ip_and_port);
							
						}
					}
					print "\n bytes_sent:$bytes_sent";
					#"if server prompt contains unprintables, send it to processchrdata"
					# and put that in the verbal report."

					# if chr / ord substr is less than 32 or more than 127, trigger chrdataproc
					#(not including cr/lfs	- 10 and 13 decimal
					 undef $temp;
					 $count = 0;
					$verbal_report = "We sent:\n";
					print "\n";
					until ($count == length ($server_prompt))	{
						 print "Count:$count \t";
						 $temp = substr ($server_prompt,$count,1);
						 if ( (ord ($temp) < 32 ) && (ord ($temp) !=13)&& (ord ($temp) !=10)||(ord ($temp) > 127))	{
							 #print "FOUND nonprinting character! It is ".ord($temp);
							 $non_printing_found = "YES";

						 }
						 $count++;
					 }
					undef $temp;
					undef $count;
					print STDOUT "non_printing_found:$non_printing_found";
					if ($non_printing_found eq "YES")	{
						print STDOUT "\n";
						print  STDOUT "Listing characters in ordinal format.";
						$count = 0;
						until ($count == length ($server_prompt))	{
							$temp = substr ($server_prompt,$count,1);
							print STDOUT " $count:".ord($temp);
							$verbal_report .= ord ($temp);
							$verbal_report .= ",";
							$count++;
						}
					}
					else	{
						$verbal_report .= "$server_prompt";
					}
					undef $temp;
					undef $count;
					undef $non_printing_found;

#					 unless ($non_printing_found eq "YES")	{
#						$verbal_report .= "$server_prompt";
#					}
					$verbal_report .=" total bytes sent:$bytes_sent";
					$verbal_report .= "\n________________________________________________________________\n";
					WriteReportFile($verbal_report, $report_filename);

					################   NMAP scan thing #################
					if ($nmap_scan)	{
						print "\n";
						print "Doing an nmap scan of $client_ip ";
						print "\n";
						$shell = `sudo nmap -Pn $client_ip >> $nmap_whois_report&`;	# NEED TO CHMOD THIS FUCKER BACK
					}

					################# WHOIS  scan thing ################
					if ($whois_scan)	{
						print "\n";
						print "Doing a whois query of $client_ip ";
						print "\n";
						$shell = `sudo whois $client_ip >> $nmap_whois_report&`;
					}
					print "\n\n";
					# If noloop was entered, will only serve you once!
					if ($noloop eq "YES")	{
						print "\n\n******************************************************";
						print "\n * No-loop mode, so ending server after 1 connection *";
						print "\n  *  If you want to listen for more, you'll just    *";
						print "\n   *   have to start malbait again!                *";
						print "\n    ***********************************************";
						print "\n Bye! \n";
						print "\n";
						die;
					}	# If noloop was entered, will only serve you once!
					
				}
			}
			#################  / Create UDP server ##########################




			#########################################################################
			################        Create TCP server     ###########################
			#########################################################################

			elsif ($transport_protocol eq 'tcp')	{
				
				print "\n\n\n\n Creating TCP server..... \n\n\n";

				$socket = socket(SERVER, PF_INET, SOCK_STREAM, getprotobyname($transport_protocol) )
				or die "\n\n ** Couldn't create socket on $server_port using $transport_protocol. Error: $! ** \n\n";


				if ($blocking == 1)	{
					unless (setsockopt(SERVER, SOL_SOCKET, SO_REUSEADDR, 1))	{ # 1= TCP? Apparently allows us to restart quickly, whatever
						$verbal_report = "\n ERROR. Couldnt' setsockopt using $transport_protocol on port $server_port. Syserr:$!";
						print "\n";
						print "************ Writing error message to $report_filename ************ ";
						print "\n";
						WriteReportFile ($verbal_report, $report_filename);
						die "\n\n ** Bottoms! Couldnt' setsockopt using $transport_protocol on port $server_port:$!** \n\n";
					}
				}

				### (Setsockopt doesn't seem to be needed for nonblocking mode, apparently!)



				$my_addr = sockaddr_in($server_port, INADDR_ANY);
				unless (bind (SERVER, $my_addr))	{


					## Oooh - err! This is probably not needed now I'm not using port 123 for anything
					#(2) Once, I had a plan to create a spoof NTP server. I decided not to bother, but just
					# in case I bring it back, here's a bit of bodge code left over from it

					#if ($server_port == 123 && $all_defaults)	{
					#	print "\n";
					#	die "\n Ignore this, it's probably just a stupid bug. \n";
					#}

					$verbal_report = "\n ERROR. Couldn't listen on $transport_protocol port $server_port. Syserr:$! (Are we root or already listening on port $server_port ?)";
					print "\n";
					print "************ Writing error message to $report_filename ************ ";
					print "\n";
					WriteReportFile ($verbal_report, $report_filename);
					die "\n\n ** Farts! Couldn't bind to port $server_port: $! (Are we root? Is something already using that port?)** \n\n";
				}
				unless (listen (SERVER, SOMAXCONN)) {
					$verbal_report = "\n ERROR. Couldn't listen on $transport_protocol port $server_port. Syserr:$! ";
					print "\n";
					print "************ Writing error message to $report_filename ************ ";
					print "\n";
					WriteReportFile ($verbal_report, $report_filename);
					die "\n\n ** Poohs! Couldn't listen on port $server_port: $! ** \n\n";
				}




				print "\n Listening on port $server_port using $transport_protocol protocol  \$!:**$!** \$@:**$@** \$.:**$.** \n";
				
				while ($read_socket = (accept (CLIENT, SERVER)) ) {
					print "\n";
					print "Successfully read socket on port $server_port! yaaay!";
					print "\n";
					
					print "\n\n\n\n\n\n\n\n\n\n\n\n\n\n";
					print "\n\n\n\n\n\n \t Forktimes:$forktimes max_requests..:$max_requests_per_server port:$server_port  protocol:$protocol";
					print "\n\n\n\n\n\n\n\n\n\n\n\n\n\n";
					#sleep 1;
					
					#print "\n\n\n RIGHT IN THE BELLY OF THE BEAST! \n\n";
					#print "Max requests per server:$max_requests_per_server";
					#print "\n\n";
					#die "debugging";

					if ($multiplexing eq "ON" && $forktimes < $max_requests_per_server) {

				# BIG, BAD, BUG! 
				
				
				#  THE FOLLOWING IS SORTED -
				# I can't tell when DoTCPServerStuff is done so I can do a  $forktimes--; 
				# in a timely manner. As-is the code will either create a shit ton of 
				# servers if there's a rush, or (if I remove the forktimes--;) 
				# only generate $max_requests_per_server servers EVER.
				#
				# The solution is to find some way I can count my child (or in this case, 
				# "grandchild" processes, and if there are more than $max_requests_per_server,
				# don't create a server.
				#
				# or keep the current code, and add code that says 
				# "if the child process has died, then $forktimes--;"





				##   THE ABOVE IS SORTED
				## Currently, doesn't allow more than max_req+1 processes. (but thats fixed now??)
				# I anticipate trouble with the temp files though. Mist check this still worx!
				
				# still unstable!
				# forktimes not decrementing properly when max_req >1
				# Also in defaults mode it might work out as max requests for ALL servers, not PER server.
				#
				# Does work well on individual servers though!
				# 
				# reaping code isn't working properly
				# Because parent isn't decrementing forktimes and isn't 
				# reaping the zombies until another process is started...
				# ifyerlucky
						
#						print "\n\n\n\n\n\n\n\n\n\n\n\n\n\n";
#						print "\n\n\n\n\n\n \t Forktimes:$forktimes max_requests..:$max_requests_per_server";
#						print "\n\n\n\n\n\n\n\n\n\n\n\n\n\n";
						#sleep 1;
						
						
						
						$grandchild_pid = fork();
						$forktimes++;
						if ($grandchild_pid == 0)	{
								print "*** MULTIPLEXING ON ***\n";
								$temp_report_filename = "TEMP-$$";	# Create tempfile
								print "\n***********\ntemp-report: $temp_report_filename\n**************\n";
								DoTCPServerStuff(	$my_addr,
												$conversation_length,
												$server_prompt,
												$protocol,
												$report_filename,
												$client_socket,
												$socket,
												$whois_scan,
												$nmap_scan,
												$temp_report_filename,
												$server_port,
												$blocking,
												$recv_buffer,
												$csv_report,
												$forktimes,
												$wait_input,
												$transblank,
												@server_conversation
												);
								$shell = `cat $temp_report_filename >> $report_filename`;
								$shell = `rm $temp_report_filename`;
								$shell = `chmod +666 $report_filename`;	# In case we're running as a Superuser
								
								print "\n\n\n ************************************************";
								print "\n * Child process $$ -  Dying / exiting on schedule * ";
								print "\n ************************************************\n\n\n\n";
								#die "\n ************************\n Child process, dying on schedule\n*****************";
								exit (0);
								
						}
						elsif ($grandchild_pid eq !defined)	{
								die "\n Can't do 2nd fork in Listener! Protocol:$protocol Port:$server_port \n";
						}

					}
					elsif ($multiplexing eq "OFF")	{

						print "\n **** MULTIPLEXING OFF ****\n";
						$temp_report_filename = "TEMP-$$";
						print "\n***********\ntemp-report: $temp_report_filename\n**************\n";
						DoTCPServerStuff(	$my_addr,
												$conversation_length,
												$server_prompt,
												$protocol,
												$report_filename,
												$client_socket,
												$socket,
												$whois_scan,
												$nmap_scan,
												$temp_report_filename,
												$server_port,
												$blocking,
												$recv_buffer,
												$csv_report,
												$forktimes,
												$wait_input,
												$transblank,
												@server_conversation
												);

						print "\n\t***I'M BACK**** \n\t report_filename:$report_filename \n\t temp-report: $temp_report_filename\n\t***********\n";
						$shell = `cat $temp_report_filename >> $report_filename`;
						$shell = `rm $temp_report_filename`;
						$shell = `chmod +666 $report_filename`;	# In case we're running as a Superuser
						print "\n************************************************************";
						print "\n* Finished DoTCPServerStuff. Back in main TCP service routine *";
						print "\n************************************************************\n";
					}
					else {
						print "\n *********************************************************************************";
						print "\n * TOO MANY CLIENTS ON $protocol port $server_port - COULDN'T CREATE ANOTHER SERVER! *";
						print "\n Debugging. \n server_prompt:$server_prompt \n grandchild_pid:$grandchild_pid ";
						print "\n forktimes: $forktimes \n max_requests_per_server: $max_requests_per_server \n protocol: $protocol";
						print "\n *********************************************************************************\n";
						shutdown (CLIENT, 2) or print "\n\n **** ERROR-Can't shutdown client: \$!:$! \$@:$@ \$.: $. ****\n\n";
						close CLIENT or print "\n\n **** ERROR-Can't close client: \$!:$! \$@:$@ \$.: $. ****\n\n";
						
					}
					
					
					
					###### CRAP ATTEMPT TO SOLVE FORKING PROBLEM - Didn't work!
							# Better, doesn't allow more than max_req... 
							# 
							
							#no... it's still really unstable!
						# I see the problem! 
						# This code ONLY RUNS if >1 clients connect at once!
#					if ($forktimes > $max_requests_per_server)	{	 already implied

## OK, I think it's OK - problem was it should have been running unconditrionally 
# *(unless multiplexing was actually switched off!)
					unless ($multiplexing eq "OFF")	{
						print "\n";
						print "\n\n\n\n\n Forktimes:$forktimes max_requests_per_server:$max_requests_per_server";
						print " port:$server_port   proto:$protocol";
						print "\n\n\n \n\n \t \t WAITING ...... \n";
						print"\n";
						print "\n Current grandchild: $grandchild_pid ";
						#sleep 1;
						print "\n";
					
						$waitresult = waitpid(-1, WNOHANG);
						print "\n\n";
						print "waitresult (main loop):$waitresult";
						
						print "\n";
						#sleep 1;
						print "\n";
						print "waited.";
						print "\n";
						print "\n************\n";
						print "* Reaping....*";
						print "\n************\n";
						$SIG{CHLD} = sub {
							print "\n\n\n \t   sending new nonblocking wait() to children....\n";
							print "\nForktimes:$forktimes max_req...$max_requests_per_server port:$server_port protocol:$protocol\n";
							#wait();
							$waitresult = waitpid(-1, WNOHANG);
							print "\n\n";
							print "waitresult (SIG{CHLD} sub):$waitresult";
							print "\n";
							$forktimes--;			
							print "\nForktimes:$forktimes max_req...$max_requests_per_server\n";
							print "\n";
							
						};
					
						print "\n";
						#sleep 1;
						print "\n";
						print "\n REAPED! Onwards to mayhem";
						print "\n";
						print "\n";
					}
					#######  crap attempt etc ############

					

					#print "\n\n\t \t\t ****** NOLOOP IS $noloop ******";
					print "\n\n";
						# If noloop was entered, will only serve you once!
					if ($noloop eq "YES")	{
						print "\n\n ****************************************";
						print "\n * No-loop mode, so not respawning server *";
						print "\n * If you want to listen for more, you'll *";
						print "\n * just have to start malbait again!      *";
						print "\n\n ****************************************";
						print "\n Bye! \n";
						print "\n";
						die;
					}	# If noloop was entered, will only serve you once!
					print "\n out of read socket loop.  \n";
					$timestamp = localtime();
					print $timestamp;

					#if ($multiplexing eq "ON") { $forktimes --;}	# Clean up after multiplexing all over the place

				} # Closes while read_socket == accept loop
				

			}	# And that's the end of my TCP server setup

			print "\n Couldn't read socket in Listen() or finished naturally, can't tell...";
			$timestamp = localtime();
			print $timestamp;

		}	# Closes while (1)
		
	}	# Closes if (fork == 0)





################### LISTENER PACKAGE SUBROUTINES ###############################

###################### DoTCPServerStuff ###############################

	# N.B. $server_prompt in UDP server is $server_output in TCP server! #


sub DoTCPServerStuff()	{

	use Errno;

	my $verbal_report;
	my $chr_data_report;
	my $client_ip;
	my $client_port;
	my $client_chr_data;
	my $conversation_report;
	my $connect_test;
	my $catch_timeout;

	my $side;
	my $data;

	my $clients_username;
	my $clients_password;
	my $count_conversation = 0;
	my $verbal_report;
	my $send_test;
	my $time;
	my $catch_timeout;
	my $fuzz_prompt;
	my $max_fuzz_len;

#	 ADDENDA for socket version
#	 (you are in DoTCPServerStuff() )
	my $my_addr = shift;
	my $raw_client_ip_and_port;
	my $raw_client_ip;
	my $connect_test;
	my $looptest;

	######################

	my $conversation_length = shift;
	my $server_prompt = shift;
	my $protocol = shift;
	my $report_filename = shift;
	my $client_socket = shift;
	my $socket = shift;
	my $whois_scan = shift;
	my $nmap_scan = shift;
	my $temp_report_filename = shift;
	my $server_port = shift;
	my $blocking = shift;
	my $recv_buffer = shift;
	my $csv_report = shift;
	my $forktimes = shift;
	my $wait_input = shift;
	my $transblank = shift;
	my @server_conversation = @_;
	my $old_dollar_dot = "different";
	my $new_dollar_dot = "not the same";

	my $shell;
	my $buffer;
	my $error_buffer;
	my $localtime;
	my $process_id;
	my $tcp_client_data;
	my $non_printing_found;
	my $bytes_sent;






# Create new report file: CSV file with
#			 "PID, Client, port,client-port, time, transport-proto, length of time connected"

	print "\n\n ********** ENTERED DoTCPServer() *********\n\n";
	print "****************************\n *transblank is $transblank\n*************************\n";
	if ($transblank eq "ON")	{
		print "\nTransblank is $transblank, so setting server_conversation to CRs (as blank as can be) \n";
		@server_conversation = chr(13);
		$server_prompt = chr(13);
		$conversation_length = 0;
		$protocol = "transblank";
	}
	###### bookmark fucking thing only blanks the first couple of entries ###

	$process_id = $$;
	unless ($raw_client_ip_and_port = getpeername(CLIENT) ) {

		print "\n ######## Can't ID client on port $server_port! $! at ".localtime()." ########\n";
		$verbal_report = "\n ####################   CAN'T IDENTIFY CLIENT!  ############################\n";
		$verbal_report .= " Couldn't ID client on port $server_port, probably an Nmap scan.";
		$verbal_report .= "\n Time:".localtime()." Process ID: $process_id System Error: (\$!): $! ";
		$verbal_report .= "\n________________________________________________________________\n";
		WriteReportFile ($verbal_report, $temp_report_filename);
		$time = localtime();
		$time =~ s/ /-/g; # Strip whitespace so it looks good in a spreadsheet
		$verbal_report = "\n$process_id,UNKNOWN,UNKNOWN,$server_port,$transport_protocol,$time";
		WriteReportFile ($verbal_report, $csv_report);
		return;
	}
	($client_port, $raw_client_ip) = unpack_sockaddr_in($raw_client_ip_and_port);
	$client_ip = inet_ntoa($raw_client_ip);

	$time = localtime();
	$time =~ s/ /-/g; # Strip whitespace so it looks good in a spreadsheet
	$verbal_report = "\n$process_id,$client_ip,$client_port,$server_port,$transport_protocol,$time";
	WriteReportFile ($verbal_report, $csv_report);



	#################################

	print "\n \t ***** TACTICAL NUKE INBOUND! ******* \n \t Connection from $client_ip $client_port ";
	print "\n *************************** GRANDCHILD ***********************";
	print "\n Debugging: \n server_prompt:$server_prompt \t grandchild_pid:#\$grandchild_pid (UNUSED)";
	print "\n forktimes:$forktimes \t max_requests_per_server: $max_requests_per_server ";
	print "\n protocol: $protocol \t  temp_report_filename:$temp_report_filename";
	print "\n **************************************************************";

	$verbal_report = "\n ############## $transport_protocol server: AN EVIL HACKER CONNECTED TO US! #########################\n";
	$verbal_report .= "\n *** ";
	unless ($noloop) {$verbal_report .= "Looptimes:$looptimes ";}
	else {$verbal_report .= " Looping OFF ";}
	$time = localtime;
	$verbal_report .= " *** Time: $time  *** ";
	$verbal_report .= "\n Them: $client_ip port $client_port";
	$verbal_report .= "\n Us: (our own IP) port $server_port";
	$verbal_report .= "\n________________________________________________________________\n";
	WriteReportFile($verbal_report, $temp_report_filename);
	
	# The 2024 email stuff should go here!
	# Will have to make it an external program, python I suppose
	#WriteReportFile ("about to do email test", "email_debug0.txt");
	if ($email_mode == "True")	{
		#WriteReportFile ("tripped email mode", "email_debug1.txt");
		
		$cmd = "python3 mail_report.py ";  
		$cmd .= $from_address;
		$cmd .= " ";
		$cmd .= $to_address;
		$cmd .= " ";
		$cmd .= $smtp_server;
		$cmd .= " ";
		$cmd .= $smtp_port;
		$cmd .= " ";
		$cmd .= $email_password;
		$cmd .= " ";
		#$cmd .= $verbal_report; #BUG!
		#$cmd .= "email_debug1.txt"
		$cmd .= $temp_report_filename;
		# What I have to do is write the email report to a text file with a random number (in case of concurrent writes - perhaps the pid?) and then read it in when running the Python mailer....
		# Hang about - the system already does this!
		#WriteReportFile($cmd, "email_debug1.txt");						
		print ("Sending this to email subprogram. ",$cmd);
		$command = `$cmd`;
		print ("I'm back! Just send the email (or tried to)");
		#WriteReportFile($cmd, "email_debug2.txt");
		#WriteReportFile($command,"email_debug3.txt");

	}
	#
	# End of 2024 bit
	
	until ($timeleft == 0)	{

		print STDOUT "\n\n ******** IN THE MAIN TCP SERVER LOOP **************";
		print STDOUT "\n  ******** I have looped $looptest times ************\n";
		close SERVER;
		select (CLIENT);
		$|=1;
		$connect_test = $!;

		if ($count_conversation > $conversation_length) { $server_conversation[$count_conversation] = $server_prompt; }
		unless ($protocol eq "echo")	{
			$server_output = $server_conversation[$count_conversation];
		}
		print STDOUT "\n **** looptest:$looptest******\n";
		$looptest++;

				# SEND THE CLIENT SOMETHING #
		if ($protocol eq "echo")	{$wait_input = "ON";}
		elsif ($protocol eq "asciitime")	{$server_output = "\n ".localtime." \n";}
		elsif ($protocol eq "bittime")	{
			#print "\n -proto:bittime option selected. Will send time in bit format (Ports 37,123 UDP)";
			$temp = time();
			$count = 0;
			until ($count == length ($temp))	{
				$server_prompt .= chr(substr ($temp, $count, 1));
				$server_conversation[0] .= chr(substr ($temp, $count, 1));
				$count++;
				#print "\n temp:$temp count:$count";
			}
		}
		elsif ($protocol eq "fuzz")	{
			unless ($wait_input eq "ON" && $count_conversation == 0)	{
				print STDOUT "\n Rolling some garbage to throw at the enemy...";
				$fuzz_prompt = "";
				$max_fuzz_len = int(rand(256));
				print STDOUT "\n Random length of random string will be $max_fuzz_len";
				print STDOUT "\n Characters generated: ";
				until (length( $fuzz_prompt ) == $max_fuzz_len)	{
					$fuzz_prompt .= chr(int(rand(256)));
					print STDOUT length( $fuzz_prompt ).",";
				}
				print STDOUT "\n  Fuzz output generated!\n";
				#print STDOUT "\n  Fuzz output:$fuzz_prompt";
				push @server_conversation, $fuzz_prompt;
				#print "\n  Server_conversation:@server_conversation";
				$server_output = $fuzz_prompt;
			}
		}

		print STDOUT "\n About to enter client-writing logics.";
		unless ($protocol eq "fuzz") {
			print STDOUT "\n  server_output:$server_output \t count_conversation:$count_conversation";
		}
		else	{
				print STDOUT "\n *** Fuzz protocol enabled, not printing sent data (may mess up terminal)";
		}

		unless ($notrans or
				$count_conversation == 0 && $wait_input eq "ON" )	{
				#or
				#$protocol eq "http" && $count_conversation > 1	)	{
			print STDOUT "\n **** WRITING TO CLIENT ***** $count_conversation \n";

			my $sendloop=0;
			until ($bytes_sent||$sendloop >99999)	{
				print STDOUT "\n Sendloop:$sendloop";
				$sendloop++;
				if ($blocking == 0)	{
					print STDOUT " NONBLOCKING MODE- SENDING...\$!:$! ";
					$bytes_sent = send (CLIENT, $server_output, MSG_DONTWAIT, $raw_client_ip_and_port);
					print STDOUT " bytes_sent:$bytes_sent";
				}
				else	{
					print STDOUT " BLOCKING MODE, SENDING...\$!:$! ";
					$bytes_sent = send (CLIENT, $server_output, 0, $raw_client_ip_and_port);
					print STDOUT " bytes_sent:$bytes_sent";
				}
			}

			print STDOUT "\n YAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY";
			print STDOUT "\n FABFABFABFAB Sent $bytes_sent to client! FABFABFABFAB";
			print STDOUT  "\n WOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOOHOOH!\n";
			undef($bytes_sent);

#			print CLIENT $server_output;	# Neurotically commented out. 
			unless ($protocol eq "fuzz")	{
				print STDOUT "\n **** JUST WROTE $server_output TO CLIENT ***** \n";
			}
			else	{
				print STDOUT "\n *** Fuzz protocol enabled, not printing sent data (may mess up terminal)";
			}
		}

		### n.b. PRINTING TO A CLOSED FILEHANDLE SEEMS TO KILL THE PROGRAM! :-o ####


		### WRITE THE SERVER'S OUTPUT TO FILE ##
		$verbal_report = " The client has contacted us $looptest times this session \n";
		$verbal_report .= " Server:";
		until ($count == length ($server_output))	{
			 #print STDOUT "\n";
			 #print STDOUT "Count:$count \t";
			 $temp = substr ($server_output,$count,1);
			 if ( (ord ($temp) < 32 ) && (ord ($temp) !=13)&& (ord ($temp) !=10)||(ord ($temp) > 127))	{
				 print  STDOUT "FOUND nonprinting character in own output! It is ".ord($temp);
				 $non_printing_found = "YES";
			 }
			 $count++;
		 }
		undef $temp;
		undef $count;
		print STDOUT "non_printing_found:$non_printing_found";
		if ($non_printing_found eq "YES")	{
			print STDOUT "\n";
			print  STDOUT "Listing characters in ordinal format.";
			$count = 0;
			until ($count == length ($server_output))	{
				$temp = substr ($server_output,$count,1);
				print STDOUT " $count:".ord($temp);
				$verbal_report .= ord ($temp);
				$verbal_report .= ",";
				$count++;
			}
		}
		else	{
			$verbal_report .= "$server_output";
		}
		undef $temp;
		undef $count;
		undef $non_printing_found;
		##############################################################

		$verbal_report .= "\n________________________________________________________________\n";
		WriteReportFile($verbal_report, $temp_report_filename);

		print STDOUT  "BEFORE CLIENT INPUT: \n *** \$.:$.***";
		$old_dollar_dot = $.;
		# Get input from client #

		$catch_timeout = eval	{		# 
			local $SIG{ALRM} = sub {die "DiNGaliNGaLINGAlING!!!\n" }; # Suicide timer
			$tcp_client_data = "";
			$buffer = "";
			alarm($timeout);		# Need to set off this alarm AT WILL.

			until ($buffer =~ "\n" || length ($buffer)==0 && length ($!)==0  || length ($tcp_client_data) > $recv_buffer )	{
				if ($blocking == 0)	{
					#print STDOUT "\n *** NONBLOCKING OPTION CONFIRMED *** \n";
					recv CLIENT, $buffer, 1, MSG_DONTWAIT;
					print STDOUT $buffer;
					$tcp_client_data .= $buffer;
					print STDOUT " SYSTEM STATUS: \$!**$!** \t \$\@:**$@** \t \$.:**$.** \n";

				}
				else	{
					#print STDOUT "\n *** BLOCKING OPTION CONFIRMED *** \n";
					recv CLIENT, $buffer, 1, MSG_WAITALL;	# Works in blocking mode
					print STDOUT $buffer;
					$tcp_client_data .= $buffer;

				}
			}



			if (length ($buffer)==0 && length ($!)==0) {
				$error_buffer = "The client shut us down!";
				print STDOUT "\n ***** WE GOT DISCONNECTED, BOSS! The client shut us down ****** \n";
				$verbal_report = " **** The client disconnected **** ";
				$verbal_report .= "\n send_test:$send_test connect_test:$connect_test \$!:$! \$_:$_ \$.:$. \$\@:$@\n";
				$verbal_report .= "Timestamp: ".localtime();
				$verbal_report .= "\n________________________________________________________________\n";
				WriteReportFile ($verbal_report, $temp_report_filename);
				alarm(0);
				last;		# If we've been disconnected, GTFO!
			}
		};


		if ($@)	{
			print STDOUT "\nCaught timeout! \$\@ = $@ . Setting \$timeleft to 0 so I can blow this joint!\n";
			$timeleft = 0;
			$localtime = localtime();
			$verbal_report = "*** We timed out *** \n no input for $timeout seconds so I disconnected their asses at $localtime";
			$verbal_report .= "\n________________________________________________________________\n";
			WriteReportFile($verbal_report, $temp_report_filename);
		}
		else	{
			print STDOUT "\n";
			print STDOUT "Catch timeout:$catch_timeout";
			print STDOUT "\n";
			$timeleft = alarm(0);		# Cancel suicide timer
			print STDOUT "\n*********************************************** ";
			print STDOUT "\n *** Timeout:$timeout ** Timeleft:$timeleft  *** ";
			unless ($protocol eq "fuzz")	{
				print STDOUT "\n *** Sent:$server_output***";
			}
			else	{
				print STDOUT "\n *** Fuzz protocol enabled,*** ";
				print STDOUT "\n ** not printing sent data *** ";
				print STDOUT "\n ** (may mess up terminal) *** ";
			}
			print STDOUT "\n ***  Recieved:$tcp_client_data ***";
			print STDOUT  "\n *** \$.:$.***";
			print STDOUT  "\n ************************************************\n ";
			$new_dollar_dot = $.;
			## 	WRITE CLIENT INPUT TO FILE ###
			$verbal_report = "";
			$side = "Client";
			$data = $tcp_client_data;

			$chr_data_report = ProcessChrData($side,$data);
			$verbal_report .= $chr_data_report;
			$verbal_report .= "\n________________________________________________________________\n";
			WriteReportFile($verbal_report, $temp_report_filename);
			$count_conversation++;
		}

		if ($protocol eq "echo") {
			print STDOUT "\n PROTOCOL IS ECHO. Setting server_output to be $tcp_client_data\n";
			$server_output = $tcp_client_data;
		}

		print STDOUT "\n End of routine. send_test:$send_test connect_test:$connect_test \$!:$! \$_:$_ \$.:$. \$\@:$@\n";
		print STDOUT "\n";

	}
	print STDOUT "\n OUT OF  '  until ( \$timeleft==0 ) { ' loop";
	print STDOUT "\n send_test:$send_test connect_test:$connect_test \$!:$! \$_:$_ \$.:$. \$\@:$@\n";

	unless (shutdown (CLIENT, 2) )	{
		print STDOUT "\n\n **** ERROR-Can't shutdown client on port $server_port: \$!:$! \$\@:$@ \$.: $. ****\n\n";
		$verbal_report = "Couldn't shutdown client $client_ip on port $client_port at ".localtime()." We're probably being NMAPped.";
		$verbal_report .= "\n________________________________________________________________\n";
		WriteReportFile($verbal_report, $temp_report_filename);

		unless (close CLIENT)	{
			print STDOUT "\n\n **** ERROR-Can't close client on port $server_port: \$!:$! \$\@:$@ \$.: $. ****\n\n";
			$verbal_report = "Oh wow, couldn't even close client $client_ip on port $client_port at ".localtime()." Again, likely NMAP.";
			$verbal_report .= "\n________________________________________________________________\n";
			WriteReportFile($verbal_report, $temp_report_filename);
		}
		unless (select (STDOUT) )	{
			print "\n\n **** ERROR-Can't select STDOUT: \$!:$! \$\@:$@ \$.: $. ****\n\n";;
			$verbal_report = "Can't select STDOUT! Client $client_ip port $server_port time".localtime(). "Now that IS unusual!";
			$verbal_report .= "\n________________________________________________________________\n";
			WriteReportFile($verbal_report, $temp_report_filename);
		}
		return;
	}


	unless (close CLIENT)	{
		print STDOUT "\n\n **** ERROR-Can't close client on port $server_port: \$!:$! \$\@:$@ \$.: $. ****\n\n";
		$verbal_report = "Oh wow, couldn't even close client $client_ip on port $client_port at ".localtime()." Again, likely NMAP.";
		$verbal_report .= "\n________________________________________________________________\n";
		WriteReportFile($verbal_report, $temp_report_filename);
		unless (select (STDOUT) )	{
			print "\n\n **** ERROR-Can't select STDOUT: \$!:$! \$\@:$@ \$.: $. ****\n\n";;
			$verbal_report = "Can't select STDOUT! Client $client_ip port $server_port time".localtime(). "Now that IS unusual!";
			$verbal_report .= "\n________________________________________________________________\n";
			WriteReportFile($verbal_report, $temp_report_filename);
		}
		return;
	}


	unless (select (STDOUT) )	{
		print "\n\n **** ERROR-Can't select STDOUT: \$!:$! \$\@:$@ \$.: $. ****\n\n";;
		$verbal_report = "Can't select STDOUT! Client $client_ip port $server_port time".localtime(). "Now that IS unusual!";
		$verbal_report .= "\n________________________________________________________________\n";
		WriteReportFile($verbal_report, $temp_report_filename);
		return;
	}

	print "\n";
	print STDOUT "Broken out of loop and closed down CLIENT socket on port $server_port! Yaaay!";
	print "\n";
#	$shell = `chmod +666 $report_filename`;	# In case we're running as a Superuser


################   NMAP scan thing #################
	if ($nmap_scan)	{
		print "\n";
		print "Doing an nmap scan of $client_ip ";
		print "\n";
		$shell = `sudo nmap -Pn $client_ip >> $nmap_whois_report&`;	# NEED TO CHMOD THIS FUCKER BACK
	}

################# WHOIS  scan thing ################
	if ($whois_scan)	{
		print "\n";
		print "Doing a whois query of $client_ip ";
		print "\n";
		$shell = `sudo whois $client_ip >> $nmap_whois_report&`;
	}

################ Reset variables ##################
	undef ($verbal_report);
	undef ($chr_data_report);
	undef ($client_ip);
	undef ($client_port);
	undef ($client_chr_data);
	undef ($conversation_report);
	undef ($connect_test);
	undef ($catch_timeout );
	undef ($socket);
	undef ($buffer);
	undef ($tcp_client_data);

	$timeleft = 1;
	$output_count = 0;
	$count_conversation = 0;
	$looptimes++;
	return;
}

#############################################################################
#####################  PROCESSCHRDATA #################################

sub ProcessChrData() {


	##########
	## Builds a data structure giving me at the very least:
	# 1) Literal chars (in case data switches between ASCII and machine code)
	# 2) Decimal translation of said chars
	#
	# Then find a fun and easy way of returning it, or putting it on disk.
	# (ideally I'd return it in an easy-to-interrogate, human-readable data structure)
	#

	my $lenstring;
	my $currentchr;
	my $string;
	my $countchr;
	my $humenumber;

	my @chr_data;
	my @ord_data;

	my $side = shift;
	my $data = shift;

	$string = $data;

	$lenstring = length($string);
	$chr_data_report = "$side :$string";
	$chr_data_report .= "\n Analysis:\n";
	$countchr = 0;
	until ($countchr == $lenstring)	{
		$currentchr = (substr $string, $countchr);
		$chr_data_report .= "\n countchr:$countchr \t currentchr:";
		$chr_data_report .= chr (ord ($currentchr));
		$chr_data_report .= "\t";
		$humenumber = ord ($currentchr);
		$chr_data_report .= " $humenumber \t ";
		$chr_data[$countchr] = chr (ord ($currentchr));
		$ord_data[$countchr] = ord ($currentchr);
		$countchr++;
	}
	return ($chr_data_report);

}



#############################################################################
############################### WriteReportFile #############################


sub WriteReportFile()	{

	# Fixed clumsy bastard that would break connection.


	use Fcntl qw/:DEFAULT :flock/;

	my $report_file_wait = 0;
	my $old_dollarbar;

	my $verbal_report = shift;
	my $report_filename = shift;
	# $verbal_report .= "\n__________________________________________\n";

	print STDOUT "\n Current device: ".select();

	# select (REP);

	print STDOUT "\n Current device: ".select();

	sysopen (REP, "$report_filename", O_WRONLY |O_APPEND | O_CREAT) or disasterola($report_filename, $verbal_report);

	$old_dollarbar = local $|;

	until (flock (REP, LOCK_EX) )	{
		#print "\n Waiting for lock on $report_filename to write $verbal_report, looped $report_file_wait times \n";
		local $| = 1;
		flock (REP, LOCK_EX) or disasterola($report_filename, $verbal_report);
		$report_file_wait++;
	}

	printf (REP "$verbal_report");

	#print STDOUT "\n Current device: ".select();

	close REP;
	#print STDOUT "\n Current device: ".select();
#	flock (REP, LOCK_UN) or disasterola(); # Uncomment this if you hget a lot of errors using this routine


	#select (CLIENT);
	#print STDOUT "\n Current device: ".select();
	return;

}

###############################################################################
################################### DISASTEROLA ###############################

sub disasterola ()	{
	my $report_filename = shift;
	my $verbal_report = shift;

# THIS IS AN INFINITE LOOP. REASON: Multitasking wld scroll a normal error message off the screen.
	DISASTER:
	print STDOUT "\n OHSHITOHSHITOHSHITOHSHITOHSHITOHSHITOHSHITOHSHITOHSHITOHSHITOHSHITOHSHITOHSHIT";
	print STDOUT "\n *** Objectivity lost, file system inacessible accessing $report_filename!     ***";
	print STDOUT "\n ** verbalreport: \n $verbal_report **";
	print STDOUT "\n OHSHITOHSHITOHSHITOHSHITOH (Ctrl-C quits) OHSHITOHSHITOHSHITOHSHITOHSHITOHSHIT";
	goto DISASTER;
}

}		################# END OF LISTENER PACKAGE ############################




