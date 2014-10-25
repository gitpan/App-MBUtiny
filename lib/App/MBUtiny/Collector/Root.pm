package App::MBUtiny::Collector::Root; # $Id: Root.pm 40 2014-08-30 10:31:47Z abalama $
use strict;

=head1 NAME

App::MBUtiny::Root - Root controller for Collector Server

=head1 VERSION

Version 1.00

=head1 SYNOPSIS

    none

=head1 DESCRIPTION

Root controller for Collector Server. No public subroutines

=head1 HISTORY

See C<CHANGES> file

=head1 TO DO

See C<TODO> file

=head1 SEE ALSO

L<App::MBUtiny>, L<WWW::MLite>, L<App::MBUtiny::Collector>

=head1 AUTHOR

Serz Minus (Lepenkov Sergey) L<http://www.serzik.com> E<lt>minus@mail333.comE<gt>

=head1 COPYRIGHT

Copyright (C) 1998-2014 D&D Corporation. All Rights Reserved

=head1 LICENSE

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
GNU General Public License for more details.

See C<LICENSE> file

=cut

use Encode;
use WWW::MLite::Util;
use CTK::Util qw/ :BASE :FORMAT /;
use CTK::ConfGenUtil;
use CTK::TFVals qw/ :ALL /;
use App::MBUtiny::Util;

#use Data::Dumper; $Data::Dumper::Deparse = 1;

use constant {
        TABLE_NAME      => 'mbutiny',
    };


sub meta {(
    default => { # ���������
        handler => {
            access  => sub {1},
            form    => [ \&App::MBUtiny::Collector::before_view, \&default_form, \&App::MBUtiny::Collector::after_view, ],
            deny    => sub {1},
            chck    => sub {1},
            proc    => sub {1},
        },
        description => to_utf8("���������"),
    },
    check => { # �������� ���������� ���������� � ������ ��������� ������������
        handler => {
            access  => \&default_access,
            form    => [ \&App::MBUtiny::Collector::before_view, \&check_form, \&App::MBUtiny::Collector::after_view, ],
            deny    => [ \&App::MBUtiny::Collector::before_view, \&App::MBUtiny::Collector::after_view ],
            chck    => sub {1},
            proc    => sub {1},
        },
        description => to_utf8("�������� ���������� ���������� � ������ ��������� ������������"),
        bd_enable   => 1,
    },
    upload => { # ���������
        handler => {
            access  => \&default_access,
            form    => [ \&App::MBUtiny::Collector::before_view, \&upload_form, \&App::MBUtiny::Collector::after_view, ],
            deny    => [ \&App::MBUtiny::Collector::before_view, \&App::MBUtiny::Collector::after_view ],
            chck    => sub {1},
            proc    => sub {1},
        },
        description => to_utf8("���������"),
        bd_enable   => 1,
    },
    fixup => { # ������������
        handler => {
            access  => \&default_access,
            form    => [ \&App::MBUtiny::Collector::before_view, \&fixup_form, \&App::MBUtiny::Collector::after_view, ],
            deny    => [ \&App::MBUtiny::Collector::before_view, \&App::MBUtiny::Collector::after_view ],
            chck    => sub {1},
            proc    => sub {1},
        },
        description => to_utf8("������������"),
        bd_enable   => 1,
    },
    list => { # ������ ������ ��� �����
        handler => {
            access  => \&default_access,
            form    => [ \&App::MBUtiny::Collector::before_view, \&list_form, \&App::MBUtiny::Collector::after_view, ],
            deny    => [ \&App::MBUtiny::Collector::before_view, \&App::MBUtiny::Collector::after_view ],
            chck    => sub {1},
            proc    => sub {1},
        },
        description => to_utf8("������ ������ ��� �����"),
        bd_enable   => 1,
    },
    delete => { # �������� ����� ��� �����
        handler => {
            access  => \&default_access,
            form    => [ \&App::MBUtiny::Collector::before_view, \&delete_form, \&App::MBUtiny::Collector::after_view, ],
            deny    => [ \&App::MBUtiny::Collector::before_view, \&App::MBUtiny::Collector::after_view ],
            chck    => sub {1},
            proc    => sub {1},
        },
        description => to_utf8("�������� ����� ��� �����"),
        bd_enable   => 1,
    },
)}

sub default_access { # �������� ���������� ����������
    my $self = shift;
    my $error   = $self->error;
    my $db      = $self->db;

    # �������� ���������� ��
    if ($db) {
        my $dbh = $db->connect;
        if ($db->err) {
            push @$error, sprintf("ERR: %s; ERRSTR: %s; STATE: %s", $db->err, $db->errstr, $db->state);
            return 0;
        } else {
            push(@$error, to_utf8("������ �����������")) && return 0 unless $dbh->ping;
        }
    } else {
        push @$error, to_utf8("������ ���������� � ����� ������. ��. ����");
        return 0
    }    
    
    return 1;
}
sub default_form { # ���������
    my $self = shift;
    my $usr     = $self->usr;
    my $error   = $self->error;
    
    push @$error, to_utf8("������� ������ ����������. ������ ��������� ������������ �������� ����� �������� check");
    return 0;
    
    #$self->set(status => 1);
    #$self->set(data => {
    #        message => [to_utf8("�� ������")]
    #    });
    #return 1;
}
sub check_form { # �������� ���������� ���������� � ������ ��������� ������������
    my $self = shift;
    my $usr     = $self->usr;
    my $error   = $self->error;
    
    my $base_dir = value($self->config->collector, "datadir") || $self->config->document_root || '.';

    # �������� ������, ���������� ����� ������������
    $self->set(status => 1);
    $self->set(data => {
            action => [
                    to_utf8("check"),
                    to_utf8("upload"),
                    to_utf8("fixup"),
                    to_utf8("status"),
                    to_utf8("list"),
                    to_utf8("download"),
                    to_utf8("delete"),
                ],
            dir => [ $base_dir ],
            message => [ 'Ok' ],
        });
    return 1;
}
sub upload_form { # ��������
    my $self = shift;
    my $q       = $self->q;
    my $usr     = $self->usr;
    my $error   = $self->error;
    
    # �a� 1. ��������� ������ � ���� XML 
    my $request = $usr->{request}; Encode::_utf8_on($request); 
    my %in_data = App::MBUtiny::Collector::read_api_xml($request);
    
    # ��� 2. ������� ������ � ������ ������ XML
    unless (%in_data && $in_data{object}) { #  && $in_data{status}
        #my $in_error = array($in_data{error});
        #push @$error, @$in_error;
        push @$error, to_utf8("����������� �������� ������ � ��������� request ��� ������� ������ �������� ���� <object>");
        push @$error, $request if $request;
        #use Data::Dumper; push @$error, Dumper(\%in_data);
        return 0;
    }

    # ��� 3. ������� ���������
    my $host = value($in_data{data} => 'host');
    my $file = value($in_data{data} => 'file');
    my $md5  = value($in_data{data} => 'md5') || '';
    my $sha1 = value($in_data{data} => 'sha1') || '';
    my $comment = value($in_data{data} => 'comment') || '';
    my $filef = $usr->{data} || '';
    
    # ��� 4. �������� ����������
    push(@$error, to_utf8("����������� ������ �������� ���� <host>")) && return 0 unless $host;
    push(@$error, to_utf8("����������� ������ �������� ���� <file>")) && return 0 unless $file;
    push(@$error, to_utf8("����������� ������ ��� �����")) && return 0 unless "$filef";
    
    # ��� 5. �������� ������. ��������
    my $base_dir = value($self->config->collector, "datadir") || $self->config->document_root || '.';
    my $data_dir = catdir($base_dir, $host); preparedir($data_dir) unless -e $data_dir;
    my $data_file = catfile($data_dir, $file);
    
    # ��� 5a. ��������������� ��������� � ��������� ������� �����. ������ ����� ��������� ������!
    my $uploadsize = _upload( $data_file, $q->upload('data') );
    push @$error, to_utf8("���� ��������� ���������. ��. ���� ����������") && return 0 unless $uploadsize;
    
    # ��� 5b. ��������� �����
    if ($md5) {
        my $fact_md5 = md5sum($data_file);
        push(@$error, sprintf(to_utf8("����������� ��������� ����������� ����� MD5. ��������� �� ����������: \"%s\"; �������� �� ������: \"%s\""), $fact_md5, $md5)) && return 0 
            unless lc($fact_md5) eq lc($md5);
    }
    if ($sha1) {
        my $fact_sha1 = sha1sum($data_file);
        push(@$error, sprintf(to_utf8("����������� ��������� ����������� ����� SHA1. ��������� �� ����������: \"%s\"; �������� �� ������: \"%s\""), $fact_sha1, $sha1)) && return 0
            unless lc($fact_sha1) eq lc($sha1);
    }
    
    # ��� 6. ������ �������� ���������� ������.
    my $db = $self->db;
    my $table = value($self->config->collector, "dbi/table") || TABLE_NAME;
    my $agent_ip    = $self->config->remote_addr || '127.0.0.1';
    my $agent_host  = lc(resolv($agent_ip) || '');
    my $server_ip   = $self->config->server_addr || '127.0.0.1';
    my $server_host = lc($self->config->server_name || resolv($server_ip) || 'localhost');
    $db->execute("INSERT INTO $table
                        (
                            `type`, `datestamp`, 
                            agent_host, agent_ip, agent_name, server_host, server_ip,
                            `status`, date_start, date_finish,
                            file_name, file_size, file_md5, file_sha1,
                            `comment`
                        )
                    VALUES
                        (
                            1, NOW(),
                            ?, ?, ?, ?, ?,
                            1, NULL, NULL,
                            ?, ?, ?, ?,
                            ?
                        )",
                    $agent_host, $agent_ip, $host, $server_host, $server_ip, 
                    $file, $uploadsize, $md5, $sha1,
                    $comment
                )->finish;
    push(@$error, sprintf("ERR: %s; ERRSTR: %s; STATE: %s", $db->err, $db->errstr, $db->state)) && return 0 if $db->err;
    
    # ��� 6a. ������� ��������� ������ ������ �������� (� ID)
    my $insertid = $db->field("SELECT id FROM $table WHERE 1 = 1
                AND `type` = 1
                AND agent_host = ?
                AND agent_ip = ?
                AND agent_name = ?
                AND file_name = ?
                AND file_size = ?
                AND date_start is NULL
                AND date_finish is NULL
                ORDER BY id DESC
            ",
                $agent_host, $agent_ip, $host, $file, $uploadsize,
            );
    push(@$error, sprintf("ERR: %s; ERRSTR: %s; STATE: %s", $db->err, $db->errstr, $db->state)) && return 0 if $db->err;
    push(@$error, to_utf8("Uploading and inserting failed! �� ������� �������� ID ��������� ������ � ��. ��������, ��� ���� ������� � ��������")) && return 0 unless $insertid;
    
    # ����� ������
    $self->set(status => 1);
    #$self->set(data => [ Dumper($q) ]);
    $self->set(data => {
            path    => [ $data_file ],
            id      => [ $insertid ],
            message => [ $uploadsize ? to_utf8("Uploading sucess") : to_utf8("Failed uploading!") ],
        });
    
    return 1;
}
sub fixup_form { # ������������
    my $self = shift;
    my $q       = $self->q;
    my $usr     = $self->usr;
    my $error   = $self->error;
    my $db      = $self->db;
    my $table   = value($self->config->collector, "dbi/table") || TABLE_NAME;

    # ����������� ������
    my $agent_ip    = $self->config->remote_addr || '127.0.0.1';
    my $agent_host  = lc(resolv($agent_ip) || '');
    my $server_ip   = $self->config->server_addr || '127.0.0.1';
    my $server_host = lc($self->config->server_name || resolv($server_ip) || 'localhost');

    
    # �a� 1. ��������� ������ � ���� XML 
    my $request = $usr->{request}; Encode::_utf8_on($request); 
    my %in_data = App::MBUtiny::Collector::read_api_xml($request);
    
    # ��� 2. ������� ������ � ������ ������ XML
    unless (%in_data && $in_data{object}) {
        #my $in_error = array($in_data{error});
        #push @$error, @$in_error;
        push @$error, to_utf8("����������� �������� ������ � ��������� request ��� ������� ������ �������� ���� <object>");
        push @$error, $request if $request;
        #use Data::Dumper; push @$error, Dumper(\%in_data);
        return 0;
    }
    
    # ��� 3. ������� ���������, �������� � ����������
    my $id = value($in_data{data} => 'id') || 0;
    my $type = value($in_data{data} => 'type') || 0;
    my $status = value($in_data{data} => 'status') ? 1 : 0;
    my $comment = value($in_data{data} => 'comment') || '';
    my $message = value($in_data{data} => 'message') || '';
    
    # ��� 4. ��������
    # ���� type = 1 (Internal/����������) �� ������� date_start -- ����� ������ = NOW()
    if ($type && is_int($type) && $type == 1) {
        
        push(@$error, to_utf8("����������� ������ �������� ���� <id>")) && return 0 unless is_int($id) && $id > 0;
        
        # ��� 4a. ������
        $db->execute("UPDATE $table
                    SET
                        date_start = NOW(),
                        `status` = ?,
                        `comment` = ?, 
                        `message` = ?
                    WHERE 1 = 1
                        AND id = ?
                        AND `type` = 1
                        AND agent_ip = ?
                    ",
                    $status, $comment, $message,
                    $id, $agent_ip
                )->finish;
        push(@$error, sprintf("ERR: %s; ERRSTR: %s; STATE: %s", $db->err, $db->errstr, $db->state)) && return 0 if $db->err;
        
        # ��� 4b. ��������� ID ����������� ������
        my $test_id = $db->field("SELECT id FROM $table WHERE 1 = 1
                AND `type` = 1
                AND id = ?
                AND agent_ip = ?
                AND date_finish IS NULL
            ",
                $id, $agent_ip
            );
        push(@$error, sprintf("ERR: %s; ERRSTR: %s; STATE: %s", $db->err, $db->errstr, $db->state)) && return 0 if $db->err;
        push(@$error, to_utf8("Fixing and updating failed! �� ������� �������� ID ������ � �� #$id. ��������, ��� ���� ������� � ��������")) && return 0 unless $test_id;
    
    } else {
        my $host = value($in_data{data} => 'host');
        my $file = value($in_data{data} => 'file');
        my $size = value($in_data{data} => 'size') || 0;
        my $md5  = value($in_data{data} => 'md5') || '';
        my $sha1 = value($in_data{data} => 'sha1') || '';
    
        push(@$error, to_utf8("����������� ������ �������� ���� <host>")) && return 0 unless $host;
        push(@$error, to_utf8("����������� ������ �������� ���� <file>")) && return 0 unless $file;
        push(@$error, to_utf8("����������� ������ �������� ���� <size>")) && return 0 unless is_int($size) && $size > 0;
        
        # ��� 4a. �����
        $db->execute("INSERT INTO $table
                        (
                            `type`, `datestamp`, 
                            agent_host, agent_ip, agent_name, server_host, server_ip,
                            `status`, date_start, date_finish,
                            file_name, file_size, file_md5, file_sha1,
                            `comment`, `message`
                        )
                    VALUES
                        (
                            0, NOW(),
                            ?, ?, ?, ?, ?,
                            ?, NOW(), NULL,
                            ?, ?, ?, ?,
                            ?, ?
                        )",
                    $agent_host, $agent_ip, $host, $server_host, $server_ip, 
                    $status,
                    $file, $size, $md5, $sha1,
                    $comment, $message
                )->finish;
        push(@$error, sprintf("ERR: %s; ERRSTR: %s; STATE: %s", $db->err, $db->errstr, $db->state)) && return 0 if $db->err;
        
        # ��� 4b. ��������� LAST_INSERT_ID ������ ��������
        $id = $db->field("SELECT id FROM $table WHERE 1 = 1
                AND `type` = 0
                AND agent_host = ?
                AND agent_ip = ?
                AND agent_name = ?
                AND file_name = ?
                AND file_size = ?
                AND date_finish IS NULL
                ORDER BY id DESC
            ",
                $agent_host, $agent_ip, $host, $file, $size,
            );
        push(@$error, sprintf("ERR: %s; ERRSTR: %s; STATE: %s", $db->err, $db->errstr, $db->state)) && return 0 if $db->err;
        push(@$error, to_utf8("Fixing and inserting failed! �� ������� �������� ID ��������� ������ � ��. ��������, ��� ���� ������� � ��������")) && return 0 unless $id;
    }

    # ����� ������
    $self->set(status => 1);
    $self->set(data => {
            id      => [ $id ],
            message => [to_utf8("Fixing sucess. The data successfully inserted to table of database")],
        });
    
    return 1;
}
sub list_form { # ������ ������ ��� �����
    my $self = shift;
    my $q       = $self->q;
    my $usr     = $self->usr;
    my $error   = $self->error;
    my $db      = $self->db;
    my $table   = value($self->config->collector, "dbi/table") || TABLE_NAME;

    # ����������� ������
    my $agent_ip    = $self->config->remote_addr || '127.0.0.1';
    my $agent_host  = lc(resolv($agent_ip) || '');
    
    # �a� 1. ��������� ������ � ���� XML 
    my $request = $usr->{request}; Encode::_utf8_on($request); 
    my %in_data = App::MBUtiny::Collector::read_api_xml($request);
    
    # ��� 2. ������� ������ � ������ ������ XML
    unless (%in_data && $in_data{object}) {
        push @$error, to_utf8("����������� �������� ������ � ��������� request ��� ������� ������ �������� ���� <object>");
        push @$error, $request if $request;
        return 0;
    }
    
    # ��� 3. ������� ���������, �������� � ����������
    my $host = value($in_data{data} => 'host');
    push(@$error, to_utf8("����������� ������ �������� ���� <host>")) && return 0 unless $host;
        
    # ��� 4. ��������� ������ ������
    my @record = map {$_ = $_->[0]} $db->table("SELECT DISTINCT file_name FROM $table WHERE 1 = 1
                AND `type` = 1
                AND agent_ip = ?
                AND agent_name = ?
                AND date_finish IS NULL      
            ",
            $agent_ip, $host,
        );
    push(@$error, sprintf("ERR: %s; ERRSTR: %s; STATE: %s", $db->err, $db->errstr, $db->state)) && return 0 if $db->err;

    # ����� ������
    $self->set(status => 1);
    $self->set(data => {
            list    => [@record],
            message => [@record ? to_utf8("������ ������ ��� ����� ������� �������") : to_utf8("������ ������ ��� ����� ����")],
        });
    
    return 1;
}
sub delete_form { # �������� ����� ��� �����
    my $self = shift;
    my $q       = $self->q;
    my $usr     = $self->usr;
    my $error   = $self->error;
    my $db      = $self->db;
    my $table   = value($self->config->collector, "dbi/table") || TABLE_NAME;

    # ����������� ������
    my $agent_ip    = $self->config->remote_addr || '127.0.0.1';
    my $agent_host  = lc(resolv($agent_ip) || '');
    
    # �a� 1. ��������� ������ � ���� XML 
    my $request = $usr->{request}; Encode::_utf8_on($request); 
    my %in_data = App::MBUtiny::Collector::read_api_xml($request);
    
    # ��� 2. ������� ������ � ������ ������ XML
    unless (%in_data && $in_data{object}) {
        push @$error, to_utf8("����������� �������� ������ � ��������� request ��� ������� ������ �������� ���� <object>");
        push @$error, $request if $request;
        return 0;
    }
    
    # ��� 3. ������� ���������, �������� � ����������
    my $host = value($in_data{data} => 'host');
    my $file = value($in_data{data} => 'file');
    push(@$error, to_utf8("����������� ������ �������� ���� <host>")) && return 0 unless $host;
    push(@$error, to_utf8("����������� ������ �������� ���� <file>")) && return 0 unless $file;
        
    # ��� 4. ��������� ID � Type ��� ������� ����� �� ������ ����������
    my ($id, $type) = $db->record("SELECT id, `type` FROM $table WHERE 1 = 1
                AND file_name = ?
                AND agent_ip = ?
                AND agent_name = ?
                AND date_finish IS NULL      
            ",
            $file, $agent_ip, $host,
        );
    push(@$error, sprintf("ERR: %s; ERRSTR: %s; STATE: %s", $db->err, $db->errstr, $db->state)) && return 0 if $db->err;
    
    # ���� ����� �� �������
    push(@$error, to_utf8("���� ����� �� ������� ��� ����������� ����������� ����� �� ��������")) && return 0 unless $id;
    
    # ��� type=1 ������� ��� ���� ��������� �� �������
    my $base_dir = value($self->config->collector, "datadir") || $self->config->document_root || '.';
    my $data_dir = catdir($base_dir, $host);
    my $data_file = catfile($data_dir, $file);
    my $msg = "File $data_file esuccessfully deleted";
    if ($type) {
        if (-e $data_file) {
            unless (unlink($data_file)) {
                $msg = "Could not unlink $data_file: $!"
            }
        } else {
            $msg = "File $data_file not exists";
        }
    } else {
        $msg = "Skipped. File $data_file is located in another storage";
    }
    #$self->syslog($msg, "debug");
    
    # ��������� ������ date_finish = NOW(),
    $db->execute("UPDATE $table
            SET
                date_finish = NOW()
            WHERE 1 = 1
                AND id = ?
            ",
            $id
        )->finish;
    push(@$error, sprintf("ERR: %s; ERRSTR: %s; STATE: %s", $db->err, $db->errstr, $db->state)) && return 0 if $db->err;
    
    # ����� ������
    $self->set(status => 1);
    $self->set(data => {
            id      => [$id],
            message => [$type ? to_utf8("���� ������� ������: $msg") : to_utf8("������ � �� ��� ������� ����� ������� �������")],
        });
    
    return 1;
}

sub _upload { # ������� ���������� ������ ����� ����� ���������� ��� 0 � ������ ��������
    my $fn = shift || '';
    my $fh = shift; # $q->upload('newfile') � ���� ��� ����� �en: $::usr{newfile}
    return 0 unless $fn && $fh;
    
    $fn =~ s/\/{2,}/\//; # �������������� ����
    
    unless (open(UPLOAD,">$fn")) {
        carp("Can't write data to file \"$fn\". Please check permissions: $!");
        return 0;
    }
    #flock(UPLOAD, 2) or die("$!: ���������� ������������� ���� ��� ������ $file");

    binmode(UPLOAD);    
    print UPLOAD <$fh>;
    close UPLOAD;
    
    my $sz = -s $fn || 0;
    return $sz;
}
1;

__END__
