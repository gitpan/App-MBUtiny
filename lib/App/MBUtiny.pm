package App::MBUtiny; # $Id: MBUtiny.pm 17 2014-08-22 18:50:53Z abalama $
use strict;

=head1 NAME

App::MBUtiny - BackUp system for Your WEBsites

=head1 VERSION

Version 1.01

=head1 SYNOPSIS

    use App::MBUtiny;

=head1 ABSTRACT

App::MBUtiny - BackUp system for Your WEBsites

=head1 DESCRIPTION

BackUp system for Your WEBsites

=head1 METHODS

=over 8

=item B<new>

    my $mbu = new App::MBUtiny( $c );

Returns object. $c -- CTK object

=item B<backup>

    my $status = $mbu->backup( [qw( ... host names ... )] );

Run BackUp for all or specified names of hosts

=item B<c>

    my $c = $mbu->c;

Returns CTK object

=item B<msg>

    print $mbu->msg;

Set/Get message. Method returns informational message of MBUtiny

=back

=head1 HISTORY

See C<CHANGES> file

=head1 DEPENDENCIES

L<CTK>

=head1 TO DO

See C<TODO> file

=head1 BUGS

* none noted

=head1 SEE ALSO

C<perl>, L<CTK>, L<WWW::MLite>

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

use vars qw/ $VERSION /;
$VERSION = '1.01';

use CTK::Util;
use CTK::ConfGenUtil;
use CTK::TFVals qw/ :ALL /;

use Text::SimpleTable;
use Digest::SHA1;
use Digest::MD5;
use File::Path; # mkpath / rmtree

use App::MBUtiny::CopyExclusive;

use constant {
    OBJECTS_DIR => 'files',
    EXCLUDE_DIR => 'excludes',
};

sub new {
    my $class = shift;
    my $c     = shift;
    croak("The method is called without the required parameter. CTK Object mismatch") unless ref($c) =~ /CTK/;
    
    my $objdir = catdir($c->datadir,OBJECTS_DIR);
    my $excdir = catdir($c->datadir,EXCLUDE_DIR);
    preparedir({
            objdir => $objdir,
            excdir => $excdir,
        });
    
    my $self = bless { 
            c   => $c,
            msg => '',
            objdir => $objdir,
            excdir => $excdir,
        }, $class;
    
    #$c->log_debug("new say: Blah-Blah-Blah");
    
    return $self;
}
sub c { return shift->{c} }
sub msg { 
    my $self = shift;
    my $s = shift;
    $self->{msg} = $s if defined $s;
    return $self->{msg};
}
sub backup {
    my $self = shift;
    my $args = array(shift);
    my $c    = $self->c;
    my $config = $c->config;
    my $ret = "";
    
    # Табличные заголовки
    my @tblfields = ( # 
            [32, 'PROCESS NAME'],
            [8,  'STATUS'],
            [42, 'DESCRIPTION OF PROCCESS / DATA OF PROCCESS'],
            [19, 'TIME'],
        );
        
    # Определяем данные архиваторов
    my $arcdef = $config->{arc};
    croak "Error! Undefined <arc> section." unless $arcdef;
    
    # Получение обработчиков
    my @joblist = $self->get_jobs;
    $c->log_debug("Start processing hosts");
    foreach my $job (sort {(keys(%$a))[0] cmp (keys(%$b))[0]} @joblist) {
        my $hostname = _name($job);
        my $hostskip = (!@$args || grep {lc($hostname) eq lc($_)} @$args) ? 0 : 1;
        my @paths_for_remove;
        $c->log_debug(sprintf("Loading configuration for host \"%s\"... %s", $hostname, ($hostskip ? 'SKIPPED' : 'LOADED') ));
        next if $hostskip;
        
        # Обработка хостов
        my $enabled  = value($job, $hostname => 'enable');
        if ($enabled) {
            $c->log_debug(sprintf("--> Begin processing: \"%s\"", $hostname));
            my $pfx = " " x 3;
            my $sendreport      = value($job, $hostname => 'sendreport') || 0;
            my $senderrorreport = value($job, $hostname => 'senderrorreport') || 0;
            my $ostat = 0;  # Статус операции
            my $ferror = 0; # Найденные ошибки: 0 - их нет / 1 - ошибки были
            
            my $tbl = Text::SimpleTable->new(@tblfields);
            
            # Step 00. Выполнение предшествующих триггеров, один за другим выполняется триггер (команда)
            #          слудует заметить, что порядок выполнения не определен!
            my $triggers = array($job, $hostname => 'trigger');
            $c->log_debug($pfx, "Step 00. Get trigger list");
            foreach my $trg (@$triggers) {
                my $exe_err = '';
                my $exe_out = exe($trg, undef, \$exe_err);
                my $exe_stt = (defined ($exe_err) && $exe_err ne '') ? 0 : 1;
                $c->log_debug($pfx, sprintf("> \"%s\": %s", $trg, $exe_stt ? 'OK' : 'ERROR'));
                $c->log_debug($pfx, sprintf("> STDOUT:\n%s\n", $exe_out)) if defined ($exe_out) && $exe_out ne '';
                $c->log_error($pfx, sprintf("> STDERROR:\n%s\n", $exe_err)) unless $exe_stt;
                $tbl->row('Trigger', ($exe_stt ? 'PASSED' : 'FAILED'), $exe_stt ? $trg : sprintf("\"%s\"\nSee log: %s", $trg, $c->logfile), localtime2date_time);
            }
            
            # Step 01. Получение списка файлов для обработки
            my $objects = array($job, $hostname => 'object');
            $tbl->row('Defined objects', (@$objects ? 'PASSED' : 'FAILED'), 'The number of objects is greater than zero', localtime2date_time);
            $c->log_debug($pfx, "Step 01. Get object list");
            
            # Step 01a. Получение списка эксклюзивных файлов для обработки (exclude)
            # <Exclude ["sample"]> # -- под этим имененм сохраняется в папкке EXCLUDE_DIR, опционально
            #    Object d:\\Temp\\exclude1 # -- отсюда берутся сами файлы
            #    Target d:\\Temp\\exclude2 # -- optional. сюда пишем папку куда произойдет коирование если не хотим чтобы было в "sample" папке
            #    Exclude file1.txt
            #    Exclude file2.txt
            #    Exclude foo/file2.txt
            # </Exclude>
            my $exclude_node = _node_correct(node($job, $hostname => "exclude"), "object");
            $c->log_debug($pfx, "Step 01a. Copy directories in exclusive mode:", @$exclude_node ? 'PASSED' : 'SKIPPED');
            foreach my $exclude (@$exclude_node) {
                # Готовим данные для эксклюзивного копирования
                my $exc_name = _name($exclude);
                my $exc_data = hash($exclude, $exc_name);
                #::debug($exc_name, Data::Dumper::Dumper($exc_data));
                my $exc_object = value($exc_data, "object");
                $c->log_warning($pfx, sprintf("Object in <Exclude \"%s\"> section missing or incorrect directory \"%s\"", $exc_name, $exc_object )) && next 
                    unless $exc_object && (-e $exc_object and -d $exc_object);
                my $exc_target = value($exc_data, "target") || catdir($c->datadir,EXCLUDE_DIR,$exc_name);
                $c->log_error($pfx, sprintf("Target directory specified in <Exclude \"%s\"> section already exists: \"%s\"", $exc_name, $exc_target )) && next 
                    if $exc_target && -e $exc_target;
                my $exc_exclude = array($exc_data, "exclude") || [];
                
                # Копирование
                $App::MBUtiny::CopyExclusive::DEBUG = 1 if $c->debugmode;
                if (xcopy($exc_object, $exc_target, $exc_exclude)) {
                    push @paths_for_remove, $exc_target;
                    push @$objects, $exc_target;
                    $c->log_debug($pfx, sprintf(" - \"%s\" => \"%s\"", $exc_object, $exc_target));
                } else {
                    $c->log_error($pfx, sprintf("Copying directory \"%s\" to \"%s\" in exclusive mode failed!", 
                            $exc_object, $exc_target
                        ));
                }
            }

            # Step 02. Проверка доступности файлов для обработки
            @$objects = grep {-e} @$objects;
            $ostat  = @$objects ? 1 : 0;
            $ferror = 1 unless $ostat;
            $tbl->row('Existing objects', $ostat ? 'PASSED' : 'FAILED', (join("\n", @$objects) || ' --- NONE --- '), localtime2date_time);
            #$tbl->hr;
            $c->log_debug($pfx, "Step 02. Check available objects (files & directories):", $ostat ? 'PASSED' : 'FAILED');
            $c->log_debug($pfx, " - \"$_\"") for @$objects;
            
            # Step 03. Формирование данных для архиватора
            my $arcname = value($job, $hostname => 'arcname') || 'tar';
            $c->log_debug($pfx, "Step 03. Store data for $arcname archivator");

            # Step 04. Получение данных почты
            my $maildata = node($job, $hostname => 'sendmail'); $maildata = node($config => 'sendmail') unless value($maildata => "to"); 
            my $usemail = value($maildata => "to") ? 1 : 0;
            $c->log_debug($pfx, "Step 04. Get MAIL data:", $usemail ? 'PASSED' : 'FAILED');
            $tbl->row('Mail data defined', $usemail ? 'PASSED' : 'FAILED', 'Mail data defined', localtime2date_time);

            # Step 05. Получение маски файлов архивов и преобразование ее согласно формату
            # Маски файлов могут иметь сложный вид, по умолчанию используется маска вида:
            #    [HOST]-[YEAR]-[MONTH]-[DAY].[EXT]
            # Ключи могут быть использованы следующие:
            #
            #    DEFAULT  -- Значение соответствующее формату [HOST]-[YEAR]-[MONTH]-[DAY].[EXT]
            #    HOST     -- Имя секции хоста
            #    YEAR     -- Год создания архива
            #    MONTH    -- Месяц создания архива
            #    DAY      -- День создания архива
            #    EXT      -- Расширение файла архива
            #    TYPE     -- Тип архива
            #
            my $arcmask = value($job, $hostname => 'arcmask') || '[HOST]-[YEAR]-[MONTH]-[DAY].[EXT]';
            $arcmask =~ s/\[DEFAULT\]/[HOST]-[YEAR]-[MONTH]-[DAY].[EXT]/gi;
            my %maskfmt = (
                    HOST  => $hostname,
                    YEAR  => '',
                    MONTH => '',
                    DAY   => '',
                    EXT   => value($arcdef, 'arc'=>$arcname=>'ext')  || '',
                    TYPE  => value($arcdef, 'arc'=>$arcname=>'type') || '',
                );
            $c->log_debug($pfx, "Step 05. Get FileMask data");
            $tbl->row('Archive mask defined', 'PASSED', $arcmask, localtime2date_time);
            
            # Step 06. Получение BU характеристик для определения сжатия файлов
            my $buday   = value($job, $hostname => 'buday') || value($config => 'buday') || 0;
            my $buweek  = value($job, $hostname => 'buweek') || value($config => 'buweek') || 0;
            my $bumonth = value($job, $hostname => 'bumonth') || value($config => 'bumonth') || 0;
            $c->log_debug($pfx, "Step 06. Get BU data");
            $tbl->row('BU data (day/week/month)', 'PASSED', sprintf("%dd/%dw/%dm",$buday,$buweek,$bumonth), localtime2date_time);

            # Step 07. Получение списка ДАТ файлов, которые нужно будет сохранить
            my @dates = $self->get_dates($buday,$buweek,$bumonth);
            $c->log_debug($pfx, "Step 07. Get date list");
            $tbl->row('Stored dates (in DIG format)', $ostat ? 'PASSED' : 'FAILED', (join(", ", @dates) || ' --- NONE --- '), localtime2date_time);

            # Step 08. Формируем ТЕСТОВЫХ имена файлов исходя из масок
            my %keepfiles;
            foreach my $td (@dates) {
                ($maskfmt{YEAR}, $maskfmt{MONTH}, $maskfmt{DAY}) = ($1,$2,$3) if $td =~ /(\d{4})(\d{2})(\d{2})/;
                $keepfiles{dformat($arcmask,\%maskfmt)} = $td;
            }
            $c->log_debug($pfx, "Step 08. Get file names for skipping");

            # Step 09. Получение списка файлов имеющихся архивов на FTP первого источника если указаны его атрибуты
            my $ftp_node = _node2anode(node($job, $hostname => 'ftp'));
            my $useftp = value($ftp_node->[0], 'ftphost') ? 1 : 0;
            my $ftplist = $useftp ? ftpgetlist($ftp_node->[0], qr/^[^.]/) : [];
            my @ftpfiles = sort {$a cmp $b} @$ftplist;
            $tbl->row('Existing FTP files', $useftp ? 'PASSED' : 'FAILED', (join("\n", @ftpfiles) || ' --- NONE --- '), localtime2date_time);
            $c->log_debug($pfx, "Step 09. FTP files list:",$useftp ? 'OK' : 'NONE');
            $c->log_debug($pfx, " - ",$_) foreach @ftpfiles;

            # Step 10. Получение списка файлов имеющихся архивов в пурвом локальном хранилище если указаны его атрибуты
            my $localdir_node = array($job, $hostname => 'local/localdir') || [];
            my $first_localdir = $localdir_node->[0];
            my $uselocal = $first_localdir ? 1 : 0;
            preparedir($first_localdir) unless $uselocal && (-e $first_localdir) && (-d _ or -l _);
            my $locallist = $uselocal ? getlist($first_localdir) : [];
            my @localfiles = sort {$a cmp $b} @$locallist;
            $tbl->row('Existing LOCAL files', $uselocal ? 'PASSED' : 'FAILED', (join("\n", @localfiles) || ' --- NONE --- '), localtime2date_time);
            $c->log_debug($pfx, "Step 10. Local files list:", $uselocal ? 'OK' : 'NONE');
            $c->log_debug($pfx," - ",$_) foreach @localfiles;

            # Step 11. Удаление старых файлов архивов на FTP
            if ($useftp) {
                $c->log_debug($pfx, "Step 11. Delete old backups on FTP");
                foreach my $ftpct (@$ftp_node) {
                    my $ftph = ftp($ftpct, 'connect');
                    my $ftpuri = sprintf("ftp://%s\@%s/%s", value($ftpct, 'ftpuser'), value($ftpct, 'ftphost'), value($ftpct, 'ftpdir'));
                    unless ($ftph) {
                        $c->log_error($pfx, sprintf("%s> ERROR: Can't connect to remote FTP server %s", $hostname, $ftpuri));
                        $tbl->row('Connect to FTP', 'FAILED', $ftpuri, localtime2date_time);
                        $ftpct->{skip} = 1;
                        $ferror = 1;
                        next;
                    };
                    foreach my $f (@ftpfiles) {
                        if ($keepfiles{$f}) {
                            $c->log_debug($pfx, " - Skipped file: \"$f\"");
                        } else {
                            if ($ftph->delete($f)) {
                                $c->log_debug($pfx, sprintf(" - Deleted file: \"%s\" on %s", $f, $ftpuri));
                            } else {
                                $c->log_error($pfx, sprintf(" - ERROR: Can't delete file \"%s\" on %s: %s", $f, $ftpuri, $ftph->message));
                                $tbl->row('Delete file on FTP', 'FAILED', sprintf("%s on %s\n%s", $f, $ftpuri, $ftph->message || ''), localtime2date_time);
                                $ferror = 1;
                            }
                        }
                    }
                    $ftph->quit() if $ftph;
                }
            } else {
                $c->log_debug($pfx, "Step 11. Delete old backups on FTP directory: SKIPPED because undefined FTP section");
            }

            # Step 12. Удаление старых файлов архивов на локальном хранилище
            if ($uselocal) {
                $c->log_debug($pfx, "Step 12. Delete old backups on LOCAL directory");
                foreach my $localdir (@$localdir_node) {
                    preparedir($localdir) unless (-e $localdir) && (-d $localdir or -l $localdir);
                    foreach my $f (@localfiles) {
                        my $ffull = catfile($localdir,$f);
                        if ($keepfiles{$f}) {
                            $c->log_debug($pfx, " - Skipped file: \"$ffull\"");
                        } else {
                            unlink $ffull;
                            $tbl->row('Delete file on Local', 'PASSED', $ffull, localtime2date_time);
                            $c->log_debug($pfx, " - Deleted file: \"$ffull\"");
                        }
                    }
                }
            } else {
                $c->log_debug($pfx, "Step 12. Deleting old backups on LOCAL directory: SKIPPED because undefined LOCAL section");
            }

            # Step 13. Сжатие во временную папку (DATADIR)
            my $cdd = date2dig(); ($maskfmt{YEAR}, $maskfmt{MONTH}, $maskfmt{DAY}) = ($1,$2,$3) if $cdd =~ /(\d{4})(\d{2})(\d{2})/;
            my $fout = dformat($arcmask,\%maskfmt);
            $c->log_debug($pfx, "Step 13. Compression file \"$fout\"");
            my $outd = catdir($c->datadir,OBJECTS_DIR);
            my $outf = catfile($outd,$fout);
            $c->fcompress(
                -list   => $objects,
                -out    => $outf,
                -arcdef => $arcdef,
            );
            $ostat = -e $outf;
            $tbl->row('Compression file', $ostat ? 'PASSED' : 'FAILED', $fout, localtime2date_time);
            $ferror = 1 unless $ostat;
            $c->log_debug($pfx, " - $outf:", $ostat ? 'DONE' : 'FAILED');
            
            # Step 13a. Генерация контролькной суммы SHA1
            my $sha1 = '';
            if (value($job, $hostname => "sha1sum")) {
                $sha1 = _sha1($outf);
                $c->log_debug($pfx, "   SHA1:", $sha1);
                $tbl->row('SHA1', $sha1 ? 'PASSED' : 'FAILED', $sha1, localtime2date_time);
            }
            
            # Step 13b. Генерация контролькной суммы MD5
            my $md5 = '';
            if (value($job, $hostname => "md5sum")) {
                $md5 = _md5($outf);
                $c->log_debug($pfx, "   MD5:", $md5);
                $tbl->row('MD5', $md5 ? 'PASSED' : 'FAILED', $md5, localtime2date_time);
            }

            # Step 14. Отправка архива в локальные хранилища
            $c->log_debug($pfx, "Step 14. Copy file \"$fout\" to LOCAL directories");
            if ($uselocal) {
                foreach my $localdir (@$localdir_node) {
                    $c->fcopy(
                        -in     => $outd,
                        -out    => $localdir, # Destination directory
                        -list   => $fout,
                    );
                    my $ffull = catfile($localdir,$fout);
                    $ostat = -e $ffull;
                    $tbl->row('Copy file to LOCAL directory', $ostat ? 'PASSED' : 'FAILED', $ffull, localtime2date_time);
                    $ferror = 1 unless $ostat;
                    $c->log_debug($pfx, " - $ffull:", $ostat ? 'DONE' : 'FAILED');
                }
            } else {
                $c->log_debug($pfx, " - $fout:", "SKIPPED because undefined LOCAL section");
            }

            # Step 15. Отправка архива по FTP
            $c->log_debug($pfx, "Step 15. Store file \"$fout\" to FTP");
            if ($useftp) {
                foreach my $ftpct (@$ftp_node) {
                    next if value($ftpct, 'skip');
                    my $ftpuri = sprintf("ftp://%s\@%s/%s", value($ftpct, 'ftpuser'), value($ftpct, 'ftphost'), value($ftpct, 'ftpdir'));
                    $c->store(
                        -connect  => $ftpct,
                        -dir      => $outd,
                        -protocol => 'ftp',
                        -cmd      => 'copy',
                        -mode     => 'bin',
                        -file     => $fout,
                    );
                    my $sf = ftpgetlist($ftpct, $fout);
                    $ostat = @$sf;
                    #sprintf("%s on %s\n%s", $f, $ftpuri, $ftph->message || '')
                    $tbl->row('Store files to FTP',  $ostat ? 'PASSED' : 'FAILED', sprintf("%s on\n%s", $fout, $ftpuri), localtime2date_time);
                    $ferror = 1 unless $ostat;
                    $c->log_debug($pfx, sprintf(" - %s on %s: %s", $fout, $ftpuri, $ostat ? 'DONE' : 'FAILED'));
                }
            } else {
                $c->log_debug($pfx, " - $fout:", "SKIPPED because undefined FTP section");
            }

            # Step 16. Удаление архива из временной папки (DATADIR)
            $c->log_debug($pfx, "Step 16. Delete temporary file \"$fout\"");
            $c->frm(
                -in       => $outd,
                -list     => $fout,
            );
            
            # Step 16a. Удаление путей paths_for_remove
            $c->log_debug($pfx, "Step 16a. Delete temporary files:") if @paths_for_remove;
            foreach my $rmo (@paths_for_remove) {
                $c->log_debug($pfx, " - \"$rmo\"");
                rmtree($rmo) if -e $rmo;
            }
            
            # формирование вывода в виде таблички
            my $tbl_rslt = $tbl->draw() || '';
            $ret .= sprintf("Host: %s; Status: %s\n", $hostname, $ferror ? 'ERROR' : 'OK');
            $ret .= sprintf("%s\n", $tbl_rslt);
            
            # Step 17. Отправка письма об статусе операции если установлен флаг отправки отчета
            if ($usemail && ($sendreport || ($senderrorreport && $ferror)) ) {
                my %ma = ();
                foreach my $k (keys %$maildata) {
                    $ma{"-".$k} = $maildata->{$k};
                }
                
                if ($c->testmode) { # Тестовый режим
                    $ma{'-to'} = $maildata->{'testmail'} || $ma{'-to'};
                    $c->log_debug($pfx, "Step 17. Sending report to TEST e-mail");
                } elsif ($senderrorreport && $ferror) { # Найдены ошибки! Значит ошибочный режим
                    $ma{'-to'} = $maildata->{'errormail'} || $ma{'-to'};
                    $c->log_debug($pfx, "Step 17. Sending report to ERROR e-mail");
                } else {
                    $c->log_debug($pfx, "Step 17. Sending report to e-mail");
                }
                
                my $testpfx = $c->testmode() ? '[TEST MODE] ' : '';
                $ma{'-subject'} ||= !$ferror
                    ? sprintf($testpfx."MBUtiny %s Report: %s", $VERSION, $hostname)
                    : sprintf($testpfx."MBUtiny %s ERROR Report: %s", $VERSION, $hostname);
                $ma{'-message'} ||= !$ferror
                    ? sprintf("Хост \"%s\" обработан без ошибок\n\n%s", $hostname, $tbl_rslt)
                    : sprintf("Хост \"%s\" обработан с ошибками\n\n%s", $hostname, $tbl_rslt);
                $ma{'-message'} .= "\n---\n"
                                 . sprintf("Generated by    : MBUtiny %s\n", $VERSION)
                                 . sprintf("Date generation : %s\n", localtime2date_time())
                                 . sprintf("MBUTiny Id      : %s\n", '$Id: MBUtiny.pm 17 2014-08-22 18:50:53Z abalama $')
                                 . sprintf("Time Stamp      : %s\n", CTK::tms())
                                 . sprintf("Configuration   : %s\n", $c->cfgfile);
                $ma{'-attach'} = _attach($ma{'-attach'}) || [];
                my $sent = send_mail(%ma);
                $c->log_debug($pfx, sprintf(" - %s:", $ma{'-to'}), $sent ? 'OK (Mail has been sent)' : 'FAILED (Mail was not sent)');
            } else {
                $c->log_debug($pfx, "Step 17. Sending report disabled by user");
            }
            
            $c->log_debug(sprintf("--> Done: \"%s\". %s", $hostname, $ferror ? 'ERROR' : 'OK'));
        } else {
            $ret .= sprintf("Host: %s; Status: %s\n\n", $hostname, 'SKIP');
            $c->log_debug(sprintf("--> Skipped \"%s\". Enable flag is off", $hostname));
        }
        
        
        #::say(Data::Dumper::Dumper(_node2anode(node($job, $hostname, "test"))));
    }
    $c->log_debug("Finish processing hosts");    
    
    $self->msg($ret);
    #$c->log_debug(Data::Dumper::Dumper(@joblist));
    
    return 1;
}


sub get_jobs { # Получение списка задач. Представляет свобой либо массив атриботуов хоста либо массив с именованными хэшами для атрибутов
    my $self = shift;
    my $c    = $self->c;
    my $config = $c->config;
    my $hosts  = node($config, "host" ); # либо вернулись хосты либо нет!
    unless ($hosts) {
        $c->log_info(sprintf("Mismatch <Host> sections in configuration file \"%s\"", $c->cfgfile));
        return ();
    }
    my @jobs = (); # работы
    if (ref($hosts) eq 'ARRAY') {
        foreach my $r (@$hosts) {
            if ((ref($r) eq 'HASH') && exists $r->{enable}) {
                push @jobs, $r;
            } elsif (ref($r) eq 'HASH') {
                foreach my $k (keys %$r) {
                    push @jobs, { $k => $r->{$k} };
                }
            } else {
                #push @jobs, @$hosts;
                # debug "!!! OOPS !!!";
            }
        }
    } elsif ((ref($hosts) eq 'HASH') && !exists $hosts->{enable}) {
        foreach my $k (keys %$hosts) {
            push @jobs, { $k => $hosts->{$k} };
        }        
    } else {
        push @jobs, $hosts;
    }
    return @jobs;
}
sub get_dates { # Возвращает список разрешенных dig-дат: все разрешенные дневные, недельные и месячные даты
    my $self = shift;
    my $buday   = shift || 0; # Дневные
    my $buweek  = shift || 0; # Недельные
    my $bumonth = shift || 0; # Месячные
    
    my %dates = ();
	my $wcnt = 0;
	my $mcnt = 0;
    
    # Установка периода, равного как максимальное количество дней отмотанных "назад"
	my $period = 7 * $buweek > $buday ? 7 * $buweek : $buday;
	$period = 30 * $bumonth if 30 * $bumonth > $period;
	# debug("period: ",$period);


	# Установка хэша дат (все разрешенные и неразрешенные дневные, недельные и месячные)
    for (my $i=0; $i<$period; $i++) {
		my ( $y, $m, $d, $wd ) = (localtime( time - $i * 86400 ))[5,4,3,6];
		my $date = sprintf( "%04d%02d%02d", ($y+1900), ($m+1), $d );
        
		if (($i < $buday)
                || (($i < $buweek * 7) && $wd == 0) # do weekly backups on sunday
                || (($i < $bumonth * 30) && $d == 1)) # do monthly backups on 1-st day of month
        {
			$dates{ $date } = 1; # Проставляем "1" на все разрешенные даты без учета количества
		} else {
			$dates{ $date } = 0; # Проставляем "0" на все НЕразрешенные даты
		}
        
        # Корректиковка с учетом нужного количества бэкапов на период
        if (($i < $buday)
                || (($wd == 0) && ($wcnt++ < $buweek))
                || (($d == 1) && ($mcnt++ < $bumonth))) 
        {
			$dates{$date} ++;
		}
        
        # Удаляем строку если она нулевая, нет смысла хранить нулевые строки
        delete $dates{$date} unless $dates{$date};
	}

    return sort keys %dates;
}

sub DESTROY {
    my $self = shift;
  
    rmtree($self->{objdir}) if $self->{objdir} && -e $self->{objdir};
    rmtree($self->{excdir}) if $self->{excdir} && -e $self->{excdir};
    1;
}

sub _name { # Получение имени обрабатываемого хоста
    my $host = hash(shift);
    my @ks = keys %$host;
    return '' unless @ks;
    return 'VIRTUAL' if exists $ks[1];
    return ($ks[0] && ref($host->{$ks[0]}) eq 'HASH') ? $ks[0] : 'VIRTUAL';
}
sub _attach { # Форматирует вложения для письма
    my $d = shift;
    return undef unless $d && ref($d) =~ /ARRAY|HASH/;
    
    my @r;
    if (ref($d) eq 'HASH') {
        push @r, $d
    } else {
        @r = @$d
    }
    
    my @cr;
    foreach my $h (@r) {
        next unless $h && ref($h) eq 'HASH';
        my %t;
        foreach (keys %$h) {
           $t{ucfirst($_)} = $h->{$_}
        }
        push @cr, {%t};
    }

    return [@cr];
}
sub _sha1 { # Генерация sha1 суммы
    my $f = shift;
    my $sha1 = new Digest::SHA1;
    my $sum = '';
    return $sum unless -e $f;
    open( my $sha1_fh, '<', $f) or (carp("Can't open '$f': $!") && return $sum);
    if ($sha1_fh) {
        binmode($sha1_fh);
        $sha1->addfile($sha1_fh);
        $sum = $sha1->hexdigest;
        close($sha1_fh);
    }
    return $sum;
}
sub _md5 { # Генерация md5 суммы
    my $f = shift;
    my $md5 = new Digest::MD5;
    my $sum = '';
    return $sum unless -e $f;
    open( my $md5_fh, '<', $f) or (carp("Can't open '$f': $!") && return $sum);
    if ($md5_fh) {
        binmode($md5_fh);
        $md5->addfile($md5_fh);
        $sum = $md5->hexdigest;
        close($md5_fh);
    }
    return $sum;
}
sub _node2anode { # Переводит ноду в массив нод
    my $n = shift;
    return [] unless $n && ref($n) =~ /ARRAY|HASH/;
    return [$n] if ref($n) eq 'HASH';
    return $n;
}
sub _node_correct { # корректирует ноду как массив таким образом чтобы использовать именованные и неименованные конструкции
    my $j = shift; # Нода
    my $kk = shift || 'object'; # тестовый ключ, "обязательны" в теле ноды атрибут
    
    my @nc = ();
    if (ref($j) eq 'ARRAY') {
        my $i = 0;
        foreach my $r (@$j) {$i++;
            if ((ref($r) eq 'HASH') && exists $r->{$kk}) {
                push @nc, { sprintf("virtual_%03d",$i) => $r };
            } elsif (ref($r) eq 'HASH') {
                foreach my $k (keys %$r) {
                    push @nc, { $k => $r->{$k} };
                }
            }
        }
    } elsif ((ref($j) eq 'HASH') && !exists $j->{$kk}) {
        foreach my $k (keys %$j) {
            push @nc, { $k => $j->{$k} };
        }        
    } else {
        push @nc, { "virtual" => $j } if defined $j;
    }
    return [@nc];
}

1;

__END__

  ... HERE BASE64 SECTION OF CONFIGURATION FILES. SEE TODO FILE FOR DETAILS ...

