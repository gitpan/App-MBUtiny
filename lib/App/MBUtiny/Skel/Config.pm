package App::MBUtiny::Skel::Config; # $Id: Config.pm 39 2014-08-30 08:57:38Z abalama $
use strict;

use CTK::Util qw/ :BASE /;

use vars qw($VERSION);
$VERSION = '1.01';

sub build {
    # ������� ������
    my $self = shift;

    my $rplc = $self->{rplc};
    $rplc->{FOO} = "FOO";
    $rplc->{BAR} = "BAR";
    $rplc->{BAZ} = "BAZ";
    
    return 1;
}
sub dirs {
    # ������ ���������� � ���� ������� � ������ �� ���

    {
            path => 'extra',
            mode => 0755,
    },
    {
            path => 'hosts',
            mode => 0755,
    },
    
}
sub pool {
    # ������� � ������������ multipart ��������
    my $pos =  tell DATA;
    my $data = scalar(do { local $/; <DATA> });
    seek DATA, $pos, 0;
    return $data;
}

1;
__DATA__

-----BEGIN FILE-----
Name: mbutiny.conf
File: mbutiny.conf
Mode: 644

#
# See Config::General for details
#

# Activate or deactivate the logging: on/off (yes/no)
# LogEnable off
LogEnable   on

# debug level: debug, info, notice, warning, error, crit, alert, emerg, fatal, except
# LogLevel debug
LogLevel warning

# The number of daily archives
# This is the number of stored past the daily archives.
# BUday 3
BUday    3

# The number of weekly archives
# This is the last weekly number of stored files. Weekly archives are those daily 
# archives that were created on Sunday.
# BUweek   3
BUweek   3

# Number of monthly archives
# This amount of stored past monthly archives. Monthly Archives are those daily archives 
# that were created on the first of each month.
# BUmonth  3
BUmonth  3

SendReport      no
SendErrorReport no

Include extra/*.conf
Include hosts/*.conf

-----END FILE-----

-----BEGIN FILE-----
Name: arc.conf
File: extra/arc.conf
Mode: 644

# Tape ARchive
<Arc tar>
    type       tar
    ext        tar
    create     tar -cpf [FILE] [LIST] 2>/dev/null
    extract    tar -xpf [FILE] [DIRDST]
    exclude    --exclude-from
    list       tar -tf [FILE]
    nocompress tar -cpf [FILE]
</Arc>

# Tape ARchive + GNU Zip
<Arc tgz>
    type       tar
    ext        tgz
    create     tar -zcpf [FILE] [LIST] 2>/dev/null
    extract    tar -zxpf [FILE] [DIRDST]
    exclude    --exclude-from
    list       tar -ztf [FILE]
    nocompress tar -cpf [FILE]
</Arc>

# GNU Zip (One file only)
<Arc gz>
    type       gz
    ext        gz
    create     gzip --best [FILE] [LIST]
    extract    gzip -d [FILE]
    exclude    --exclude-from
    list       gzip -l [FILE]
    nocompress gzip -0 [FILE] [LIST]
</Arc>

# ZIP
<Arc zip>
    type       zip
    ext        zip
    create     zip -rqqy [FILE] [LIST]
    extract    unzip -uqqoX [FILE] [DIRDST]
    exclude    -x\@
    list       unzip -lqq
    nocompress zip -qq0
</Arc>

# bzip2 (One file only)
<Arc bz2>
    type       bzip2 
    ext        bz2
    create     bzip2 --best [FILE] [LIST]
    extract    bzip2 -d [FILE]
    exclude    --exclude-from
    list       bzip2 -l [FILE]
    nocompress bzip2 --fast [FILE] [LIST]
</Arc>

# RAR
<Arc rar>
    type       rar
    ext        rar
    create    rar a -r -ol -y [FILE] [LIST]
    extract    rar x -y [FILE] [DIRDST]
    exclude    -x\@
    list       rar vb
    nocompress rar a -m0
</Arc>

-----END FILE-----

-----BEGIN FILE-----
Name: arc.conf
File: extra/arc.conf
Mode: 644
Type: Windows

#######################
#
# ������ ������ � ��������. �������� ��. � ������ CTK
# 
# � ���� ������ ������������ �������� ��������� ������ � ��������,
# ������ �������� ������ ��������� �������������� ������ ���������� ��������� �����.
# ����� � ����� ����� ���� ������������ ���������:
#
# ��� ������ ���������� ������ �� �����:
#    FILE     -- ������ ��� ����� � �����
#    FILENAME -- ������ ��� ������ �������
#    DIRSRC   -- ������� ������ ���� ������
#    DIRIN    -- = DIRSRC
#    DIRDST   -- ������� ��� ����������� ����������� �������
#    DIROUT   -- = DIRDST
#    LIST     -- ������ ������ � ������, ����� ������
#    EXC      -- 'exclude file' !!!���������������!!!
#
# ��� ������ ������ ������ ������������ ��������� ����� ������:
#    FILE     -- ������ ��� ��������� ����� ������ � �����
#    DIRSRC   -- ������� ������ ���� ������ � ������������ ��� ������
#    DIRIN    -- = DIRSRC
#    LIST     -- ������ ������ ��� ������, ����� ������
#    EXC      -- 'exclude file' !!!���������������!!!
#
# ��� ������� ����� ����������� ������ � ����������� tar
# 
# <Arc tgz> # ������ ����������� ������. ���, ��� �������, ��� ���������� ������ ������
#    type       tar                       # ��� ������, ��� ������ �����
#    ext        tgz                       # ���������� ������ ������
#    create     tar -zcpf [FILE] [LIST]   # ������� ��� �������� ������
#    extract    tar -zxpf [FILE] [DIRDST] # ������� ��� ���������� ������ �� ������
#    exclude    --exclude-from            # !!!���������������!!!
#    list       tar -ztf [FILE]           # ������� ��� ��������� ������ ������ � ������
#    nocompress tar -cpf [FILE]           # ������� ��� �������� ������ ��� ������
# </Arc>
#
######################

# Tape ARchive
<Arc tar>
    type       tar
    ext        tar
    create     tar -cpf [FILE] [LIST] 2>NUL
    extract    tar -xpf [FILE] [DIRDST]
    exclude    --exclude-from
    list       tar -tf [FILE]
    nocompress tar -cpf [FILE]
</Arc>

# Tape ARchive + GNU Zip
<Arc tgz>
    type       tar
    ext        tgz
    create     tar -cvf %TEMP%/mbutiny_arch.tar [LIST] 2>NUL \
               && gzip --best -S .tmp %TEMP%/mbutiny_arch.tar \
               && mv %TEMP%/mbutiny_arch.tar.tmp [FILE]
    extract    tar -zxpf [FILE] [DIRDST]
    exclude    --exclude-from
    list       tar -ztf [FILE]
    nocompress tar -cpf [FILE]
</Arc>

# GNU Zip (One file only)
<Arc gz>
    type       gz
    ext        gz
    create     gzip --best [FILE] [LIST]
    extract    gzip -d [FILE]
    exclude    --exclude-from
    list       gzip -l [FILE]
    nocompress gzip -0 [FILE] [LIST]
</Arc>

# ZIP
<Arc zip>
    type       zip
    ext        zip
    create     zip -rqq [FILE] [LIST]
    extract    unzip -uqqoX [FILE] -d [DIRDST]
    exclude    -x\@
    list       unzip -lqq
    nocompress zip -qq0
</Arc>

# bzip2 (One file only)
<Arc bz2>
    type       bzip2 
    ext        bz2
    create     bzip2 --best [FILE] [LIST]
    extract    bzip2 -d [FILE]
    exclude    --exclude-from
    list       bzip2 -l [FILE]
    nocompress bzip2 --fast [FILE] [LIST]
</Arc>

# RAR
<Arc rar>
    type       rar
    ext        rar
    create     rar a -r -y -ep2 [FILE] [LIST]
    extract    rar x -y [FILE] [DIRDST]
    exclude    -x\@
    list       rar vb
    nocompress rar a -m0
</Arc>

-----END FILE-----

-----BEGIN FILE-----
Name: sendmail.conf
File: extra/sendmail.conf
Mode: 644

<SendMail>
    To          to@example.com
    Cc          cc@example.com
    From        from@example.com
    TestMail    test@example.com
    ErrorMail   error@example.com
    Charset     windows-1251
    Type        text/plain
    #Sendmail   /usr/sbin/sendmail
    #Flags      -t
    SMTP        192.168.0.1
    
    # Authorization SMTP
    #SMTPuser   user
    #SMTPpass   password

    # Attachment files
    #<Attach>
    #    Filename    doc1.txt 
    #    Type        text/plain 
    #    Disposition attachment
    #    Data        "Document 1. Content"
    #</Attach>
    #<Attach>
    #    Filename    mbutiny.log
    #    Type        text/plain
    #    Disposition attachment
    #    Path        /var/log/mbutiny.log
    #</Attach>
</SendMail>

-----END FILE-----

-----BEGIN FILE-----
Name: collector.conf
File: extra/collector.conf
Mode: 644

# See also collector.cgi.sample file
<Collector>
###
### !!! WARNING !!!
###
### Before using the collector-server, please check your DataBase and create the table "mbutiny"
###
#CREATE TABLE `mbutiny` (
#  `id` int(11) NOT NULL auto_increment,
#  `type` int(2) default '0' COMMENT '0 - external backup / 1 - internal backup',
#  `datestamp` datetime NOT NULL default '0000-00-00 00:00:00',
#  `agent_host` varchar(255) collate utf8_bin default NULL,
#  `agent_ip` varchar(40) collate utf8_bin default NULL,
#  `agent_name` varchar(255) collate utf8_bin default NULL,
#  `server_host` varchar(255) collate utf8_bin default NULL,
#  `server_ip` varchar(40) collate utf8_bin default NULL,
#  `status` int(2) default '0' COMMENT '0 - Error / 1 - OK',
#  `date_start` datetime default NULL,
#  `date_finish` datetime default NULL,
#  `file_name` varchar(255) collate utf8_bin default NULL,
#  `file_size` int(11) default NULL,
#  `file_md5` varchar(32) collate utf8_bin default NULL,
#  `file_sha1` varchar(40) collate utf8_bin default NULL,
#  `message` text collate utf8_bin,
#  `comment` text collate utf8_bin,
#  PRIMARY KEY  (`id`),
#  UNIQUE KEY `id` (`id`)
#) ENGINE=MyISAM DEFAULT CHARSET=utf8 COLLATE=utf8_bin;

    # Directory for backup files. 
    # Default: current directory of Your web-server (DOCUMENT_ROOT)
    # DataDir   "/var/data/mbutiny"

    # Section for connection with Your database. Recommended for use follow databases:
    # MySQL, Oracle, PostgreSQL (pg) and SQLite
    # MySQL example:
    <DBI>
        DSN         "DBI:mysql:database=mbutiny;host=mysql.example.com"
        User        username
        Password    password
        Table       mbutiny
        Set RaiseError          0
        Set PrintError          0
        Set mysql_enable_utf8   1
    </DBI>

    # Oracle Example
    #<DBI>
    #    DSN        "dbi:Oracle:PRODT"
    #    User       username
    #    Password   password
    #    Table      mbutiny
    #    Set RaiseError 0
    #    Set PrintError 0
    #</DBI>

    # SQLite example:
    #<DBI>
    #    DSN        "dbi:SQLite:dbname=test.db"
    #    Table      mbutiny
    #    Set RaiseError     0
    #    Set PrintError     0
    #    Set sqlite_unicode 1
    #</DBI>
</Collector>

-----END FILE-----

-----BEGIN FILE-----
Name: host-foo.conf.sample
File: hosts/host-foo.conf.sample
Mode: 644

<Host foo>
    Enable          yes
    SendReport      no
    SendErrorReport yes

    ArcName         tgz
    ArcMask         [HOST]-[YEAR]-[MONTH]-[DAY].[EXT]

    BUday           3
    BUweek          3
    BUmonth         3

    SHA1sum         yes
    MD5sum          yes

    # Triggers
    Trigger mkdir ./test
    Trigger mkdir ./test/mbu_sample
    Trigger mkdir ./test/mbu_sample/test
    Trigger echo foo > ./test/mbu_sample/foo.txt
    Trigger echo bar > ./test/mbu_sample/bar.txt
    Trigger echo baz > ./test/mbu_sample/baz.txt
    Trigger ls -la > ./test/mbu_sample/test/dir.lst
    #Trigger mysqldump -f -h mysql.host.com -u user --port=3306 --password=password \
    #        --add-drop-table --default-character-set=utf8 \
    #        --databases databasename > ./test/mbu_sample/test/databasename.sql
    
    # Objects
    Object ./test/mbu_sample/foo.txt
    Object ./test/mbu_sample/bar.txt
    Object ./test/mbu_sample/baz.txt
    Object ./test/mbu_sample/test

    # Exlusive objects (Can be defined by several sections)
    <Exclude "exclude_sample">
         Object ./test/mbu_sample
         #Target ./test/mbu_sample_target

         Exclude bar.txt
         Exclude test/dir.lst
    </Exclude>

    # SendMail functions (optional)
    # See extra/sendmail.conf for details
    <SendMail>
        To          to@example.com
        Cc          cc@example.com
        From        from@example.com
        Testmail    test@example.com
        Errormail   error@example.com
        Charset     windows-1251
        Type        text/plain
        #Sendmail    /usr/sbin/sendmail
        #Flags       -t
        Smtp        192.168.0.1
        #SMTPuser user
        #SMTPpass password
        #<Attach>
        #    Filename    foo.log
        #    Type        text/plain
        #    Disposition attachment
        #    Path        /var/log/mbutiny-foo.log
        #</Attach>
    </SendMail>
    
    # Collector definitions (Can be defined by several sections)
    #<Collector>
    #    URI         https://user:password@collector.example.com/collector.cgi
    #    #User       user # Optional. See URI
    #    #Password   password # Optional. See URI
    #    Comment     HTTP said blah-blah-blah for collector # Optional for collector
    #    #TimeOut    180
    #</Collector>

    # Local storage
    <Local>
        FixUP       off
        Localdir    ./test/mbutimy-local1
        Localdir    ./test/mbutimy-local2
        #Comment    Local said blah-blah-blah for collector # Optional for collector
    </Local>

    # FTP storage (Can be defined by several sections)
    #<FTP>
    #    FixUP       on
    #    FTPhost     ftp.example.com
    #    FTPdir      mbutiny/foo
    #    FTPuser     user
    #    FTPpassword password
    #    Comment     FTP said blah-blah-blah for collector # Optional for collector
    #</FTP>

    # HTTP storage (Can be defined by several sections)
    #<HTTP>
    #    FixUP       on
    #    URI         https://user:password@collector.example.com/collector.cgi
    #    #User       user # Optional. See URI
    #    #Password   password # Optional. See URI
    #    Comment     HTTP said blah-blah-blah for collector # Optional for collector
    #    #TimeOut    180
    #</HTTP>

</Host>
-----END FILE-----

-----BEGIN FILE-----
Name: host-foo.conf.sample
File: hosts/host-foo.conf.sample
Mode: 644
Type: Windows

#######################
#
# ������ ������ � ����������� ������
# 
# � ���� ������ ����������� ��������� ����������� ����������� �����.
# ����, � ������ ������� mbutiny - ��� ���������, ����������� ����� ��������
# ��� ������ � �������� � ������������ ������� ����������, ��������� ��� ����
# ���� ����� ������ � ����������, �������� �� ���������� ������������� �
# ������� �� ���������.
# ����� ������� ��������� ������, ������� ����� �������� � ������ �����:
#
#    <SendMail>, <FTP>, <Local> � ������
#
# ���� �����-���� ��������� �� ����� ����������, �� �� �������� ����� 
# ������������ �� ������ �� ���������.
#
# ������ ��������� �� ��������� ArcMask. ArcMask ��������� �� ��, �� ������
# ������� (�����) ������� ����� ��������������� ������. ����� ������ ����� 
# ����� ������� ���, �� �� ��������� ������������ ����� ����:
#
#    [HOST]-[YEAR]-[MONTH]-[DAY].[EXT]
#
# ����� ����� ����� ���� ������������ ���������:
#
#    DEFAULT  -- �������� ��������������� ������� [HOST]-[YEAR]-[MONTH]-[DAY].[EXT]
#    HOST     -- ��� ������ �����
#    YEAR     -- ��� �������� ������
#    MONTH    -- ����� �������� ������
#    DAY      -- ���� �������� ������
#    EXT      -- ���������� ����� ������
#    TYPE     -- ��� ������
#
######################
<Host foo>
    # ��������� ��� ���������� �����. �������� ������ �� ���������
    # ���� ������� ����������, �� ��������� ����� ����������, ����� ���� ������������.
    Enable      yes

    # ��������� ��� ���������� �������� ������ � ������� ������
    # ���� "��������" SendReport �� �������� SendErrorReport ������������ 
    SendReport  no

    # ��������� ��� ���������� �������� ������ � ������� ������ ������ � ������ �������.
    # ���� "��������" SendReport �� �������� SendErrorReport ������������ 
    SendErrorReport yes

    # ��� ������� �����������. ��. ���� extra/arc.conf
    ArcName     zip

    # ����� ������ �������. ��. �������� ����
    ArcMask [HOST]-[YEAR]-[MONTH]-[DAY].[EXT]
  
    # ���������� ���������� �������
    # ��� ���������� �������� ��������� ���������� �������.
    BUday       3

    # ���������� ������������ �������
    # ��� ���������� �������� ��������� ������������ �������. 
    # ������������� �������� ��������� �� ���������� ������,
    # ������� ���� ������� � �����������.
    BUweek      3

    # ���������� ����������� �������
    # ��� ���������� �������� ��������� ����������� �������. 
    # ������������ �������� ��������� �� ���������� ������,
    # ������� ���� ������� ������� ����� ������� ������.
    BUmonth     3

    # �� ���������� �������� ������ ���������� ������� ����������� ���� 
    # SHA1 � MD5. ������ ���� ���������� ������������ ��� �������� ��������
    # ����������� ������� � ��������������, � ����� ��� ������ � �����������
    SHA1sum     yes
    MD5sum      yes

    # ��������. ��� �������, ������������� �� ���� ��� ����� ����������� �������� 
    # ������ �������������� ���������. �������� ����������� ���� �� ������, �� �������
    # �� ���������� �������� �������������. ��� ���������� ���������� �������
    # ������� ������������ ������� ������� ��� �������� �� � ��������� �������
    Trigger mkdir C:\\Temp\\mbu_sample
    Trigger mkdir C:\\Temp\\mbu_sample\\test
    Trigger echo foo > C:\\Temp\\mbu_sample\\foo.txt
    Trigger echo bar > C:\\Temp\\mbu_sample\\bar.txt
    Trigger echo baz > C:\\Temp\\mbu_sample\\baz.txt
    Trigger dir > C:\\Temp\\mbu_sample\\test\\dir.lst
    #Trigger mysqldump -f -h mysql.host.com -u user --port=3306 --password=password \
    #        --add-drop-table --default-character-set=utf8 \
    #        --databases databasename > C:\\Temp\\mbu_sample\\test\\databasename.sql
    
    # ������ ���� �������� ��� ��������� (��������� ����� � �����)
    Object C:\\Temp\\mbu_sample\\foo.txt
    Object C:\\Temp\\mbu_sample\\bar.txt
    Object C:\\Temp\\mbu_sample\\baz.txt
    Object C:\\Temp\\mbu_sample\\test

    # ������ ������������� ����������� ��������. ������ ��������� ���������� ����� � 
    # ����� �������� ���������� � ��������� Object � ������� ������� ������������
    # � ������ ��������� Target. ����������� ���������� ���� ��������� ��������� 
    # �������� � ������� ������� �������� �������, ��������� �� ����������
    # ���������� Exclude. ������ ������ �������� �������� ������� ��������������� 
    # ���������� �����.
    <Exclude "exclude_sample">
         # ������ ������� ���� �����. ��������� ����� ���� ������ ����
         Object C:\\Temp\\mbu_sample

         # �����������. ���� ���������� �������
         #Target C:\\Temp\\mbu_sample_target

         # ������������� ���� ������ � �����
         Exclude bar.txt
         Exclude test/dir.lst
    </Exclude>


    # ��������� SendMail � ��������� �������� �����
    # ����� ��������� ���������� ��. � ����� extra/sendmail.conf
    <SendMail>
        To          to@example.com
        Cc          cc@example.com
        From        from@example.com
        Testmail    test@example.com
        Errormail   error@example.com
        Charset     windows-1251
        Type        text/plain
        Smtp        192.168.0.1
        #SMTPuser user
        #SMTPpass password
        #<Attach>
        #    Filename    foo.log
        #    Type        text/plain
        #    Disposition attachment
        #    Path        /var/log/mbutiny-foo.log
        #</Attach>
    </SendMail>

    # ��������� ����������. ������ ����� ���� ���������� ���������
    # URI         - ����� URI �� ��������� (����������). ����� � ������ HTTP �����������
    #               ����������� ���� � URI ���� ��������, ���� ��� ������� ������������.
    # TimeOut     - �������. �� ��������� 180 ������.
    #<Collector>
    #    URI         https://user:password@collector.example.com/collector.cgi
    #    #User       user # Optional. See URI
    #    #Password   password # Optional. See URI
    #    #TimeOut    180
    #</Collector>

    # ��������� ���������� ���������, ��� ��������� �� �������� ��������,
    # ���� ��� ����� ������������ �� �������� ������� ������������ �������
    # ����������� ���������� (�������, ����������, ���������, �������������� � �.�.)
    <Local>
        # �������� ���� ���� ���������, ����� ��������� ����������� ������ � 
        # ��������� ��������� ��������� 
        FixUP       off
        Localdir    C:\\Temp\\mbutimy-local1
        Localdir    C:\\Temp\\mbutimy-local2
        #Comment    Local said blah-blah-blah for collector # Optional for collector
    </Local>

    # ��������� ���������� FTP-���������
    # FTPhost     - ����� ��� �������� ��� FTP �������
    # FTPdir      - ���������� �������� �������. ��� ������� ����� ����� ���� ����������
    # FTPuser     - ��� ������������ FTP �������
    # FTPpassword - ������ ������������ FTP �������
    # FixUP       - on/off - ��������� ��������� �������� ���������� ������ �� ����������
    # Comment     - ����������� ��� ����������. ������� ��� �����������
    # ������ <FTP> ����� ���� ���������. � ���� ������ ���������� ������ ��� ������
    # FTP-����������
    #<FTP>
    #    FixUP       on
    #    FTPhost     ftp.example.com
    #    FTPdir      mbutiny/foo
    #    FTPuser     user
    #    FTPpassword password
    #    Comment     FTP said blah-blah-blah for collector # Optional for collector
    #</FTP>
    
    # ��������� ���������� HTTP-���������
    # URI         - ����� URI �� ��������� (����������). ����� � ������ HTTP �����������
    #               ����������� ���� � URI ���� ��������, ���� ��� ������� ������������.
    # FixUP       - on/off - ��������� ��������� �������� ���������� ������ �� ����������
    #               ������� ���������, ��� ��������� ��� ���������� ������� �������� 
    #               ��������� �������, �.�. ����� ����� �������� �� ����� ���������� �
    #               ������ � ������� �� ������
    # Comment     - ����������� ��� ����������. ������� ��� �����������
    # TimeOut     - �������. �� ��������� 180 ������. ������� �������� ���� ������ ������
    #               ����������� �������, � �� �������� ������ �� ��������� ��������
    #               ���������. 
    # ������ <HTTP> ����� ���� ���������. � ���� ������ ���������� ������ ��� ������
    # HTTP-����������
    #<HTTP>
    #    FixUP       on
    #    URI         https://user:password@collector.example.com/collector.cgi
    #    #User       user # Optional. See URI
    #    #Password   password # Optional. See URI
    #    Comment     HTTP said blah-blah-blah for collector # Optional for collector
    #    #TimeOut    180
    #</HTTP>
</Host>
-----END FILE-----

-----BEGIN FILE-----
Name: collector.cgi.sample
File: collector.cgi.sample
Mode: 644

#!/usr/bin/perl -w
use strict;

use WWW::MLite;
my $mlite = new WWW::MLite(
        prefix  => 'collector',
        name    => 'Collector',
        module  => 'App::MBUtiny::Collector',
        config_file => '/path/to/mbutiny/extra/collector.conf',
        register => ['App::MBUtiny::Collector::Root'],
    );
$mlite->show;

-----END FILE-----
