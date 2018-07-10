use strict;
use warnings;
use ExtUtils::MakeMaker;

WriteMakefile(
    NAME                => 'Dancer2::Plugin::Auth::Extensible::Provider::KankuLDAP',
    AUTHOR              => q{Frank Schreiner <fschreiner@suse.de>},
    VERSION_FROM        => 'lib/Dancer2/Plugin/Auth/Extensible/Provider/KankuLDAP.pm',
    ABSTRACT_FROM       => 'lib/Dancer2/Plugin/Auth/Extensible/Provider/KankuLDAP.pm',
    ($ExtUtils::MakeMaker::VERSION >= 6.48
      ? ('MIN_PERL_VERSION'=> '5.6.0')
      : ()),
    ($ExtUtils::MakeMaker::VERSION >= 6.48
      ? ('LICENSE'=> 'perl')
      : ()),
    BUILD_REQUIRES => {
        'Test::More'      => 0,
        'Test::Net::LDAP' => '0.07',
    },
    PREREQ_PM => {
        'Carp'                              => 0,
        'Dancer2::Core::Types'              => 0,
        'Dancer2::Plugin::Auth::Extensible' => '0.620',
        'Moo'                               => '2.000000',
        'namespace::clean'                  => 0,
        'Net::LDAP'                         => 0,
        'YAML' => 0,    # for config files and tests
    },
    dist  => { COMPRESS => 'gzip -9f', SUFFIX => 'gz', },
    clean => { FILES => 'Dancer2-Plugin-Auth-Extensible-Provider-KankuLDAP*' },
    META_MERGE => {
        resources => {
            repository => 'https://github.com/M0ses/Dancer2-Plugin-Auth-Extensible-Provider-KankuLDAP',
            bugtracker => 'https://github.com/M0ses/Dancer2-Plugin-Auth-Extensible-Provider-KankuLDAP/issues',
            homepage   => 'https://github.com/M0ses/Dancer2-Plugin-Auth-Extensible-Provider-KankuLDAP/',
        },
    },
);
