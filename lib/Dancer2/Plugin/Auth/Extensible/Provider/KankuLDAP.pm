package Dancer2::Plugin::Auth::Extensible::Provider::KankuLDAP;

use Carp qw/croak/;
use Dancer2::Core::Types qw/HashRef Str Bool Object/;
use Net::LDAP;

use Moo;
with "Dancer2::Plugin::Auth::Extensible::Role::Provider";
use namespace::clean;
use DateTime;

our $VERSION = '0.704';

=head1 NAME

Dancer2::Plugin::Auth::Extensible::Provider::KankuLDAP - Authentication provider for Dancer2::Plugin::Auth::Extensible mixing LDAP and local database

=head1 DESCRIPTION

This class mixes LDAP based authentication with database authorization

See L<Dancer2::Plugin::Auth::Extensible> for details on how to use the
authentication framework.

=head1 ATTRIBUTES

=head2 host

The LDAP host name or IP address passed to L<Net::LDAP/CONSTRUCTOR>.

Required.

=cut

has host => (
    is       => 'ro',
    isa      => Str,
    required => 1,
);

=head2 options

Extra options to be passed to L<Net::LDAP/CONSTRUCTOR> as a hash reference.

=cut

has options => (
    is      => 'ro',
    isa     => HashRef,
    default => sub { +{} },
);

=head2 basedn

The base dn for all searches (e.g. 'dc=example,dc=com').

Required.

=cut

has basedn => (
    is       => 'ro',
    isa      => Str,
    required => 1,
);

=head2 binddn

This must be the distinguished name of a user capable of binding to
and reading the directory (e.g. 'cn=admin,dc=example,dc=com').

=cut

has binddn => (
    is       => 'ro',
    isa      => Str,
);

=head2 bindpw

The password for L</binddn>.

=cut

has bindpw => (
    is       => 'ro',
    isa      => Str,
);

=head2 noauth

Don't use authentication for bind.

=cut

has noauth => (
    is       => 'ro',
    isa      => Bool,
);

=head2 username_attribute

The attribute to match when searching for a username.

Defaults to 'cn'.

=cut

has username_attribute => (
    is      => 'ro',
    isa     => Str,
    default => 'cn',
);

=head2 name_attribute

The attribute which contains the full name of the user. See also:

L<Dancer2::Plugin::Auth::Extensible::Role::User/name>.

Defaults to 'displayName'.

=cut

has name_attribute => (
    is      => 'ro',
    isa     => Str,
    default => 'displayName',
);

=head2 user_filter

Filter used when searching for users.

Defaults to '(objectClass=person)'.

=cut

has user_filter => (
    is      => 'ro',
    isa     => Str,
    default => '(objectClass=person)',
);

=head2 role_attribute

The attribute used when searching for role names.

Defaults to 'cn'.

=cut

has role_attribute => (
    is      => 'ro',
    isa     => Str,
    default => 'cn',
);

=head2 role_filter

Filter used when searching for roles.

Defaults to '(objectClass=groupOfNames)'

=cut

has role_filter => (
    is      => 'ro',
    isa     => Str,
    default => '(objectClass=groupOfNames)',
);

=head2 role_member_attribute

The attribute who's value should be a user's DN to show the user has the
specific L</role_attribute>'s value.

Defaults to 'member'.

=cut

has role_member_attribute => (
    is      => 'ro',
    isa     => Str,
    default => 'member',
);

=head2 role_search_attribute

The user's attribute to search for in role lookup

Defaults to 'dn'.

=cut

has role_search_attribute => (
    is      => 'ro',
    isa     => Str,
    default => 'dn',
);

has dancer2_plugin_dbic => (
    is      => 'ro',
    lazy    => 1,
    default => sub { $_[0]->plugin->app->with_plugin('Dancer2::Plugin::DBIC') },
    handles => { dbic_schema => 'schema' },
    init_arg => undef,
);

has schema_name => ( is => 'ro', );

has schema => (
    is      => 'ro',
    lazy    => 1,
    default => sub {
        my $self = shift;
        $self->schema_name
          ? $self->dbic_schema( $self->schema_name )
          : $self->dbic_schema;
    },
);

=head1 METHODS

=head2 ldap

Returns a connected L<Net::LDAP> object.

=cut

sub ldap {
    my $self = shift;
    Net::LDAP->new( $self->host, %{ $self->options } )
      or croak "LDAP connect failed for: " . $self->host;
}

=head2 authenticate_user $username, $password

=cut

sub authenticate_user {
    my ( $self, $username, $password ) = @_;

    croak "username and password must be defined"
      unless defined $username && defined $password;

    my $user = $self->get_user_details($username) or return;

    my $ldap = $self->ldap or return;

    my $mesg = $ldap->bind( $user->{dn}, password => $password );

    $ldap->unbind;
    $ldap->disconnect;

    return not $mesg->is_error;
}

=head2 get_user_details $username

=cut

sub get_user_details {
    my ( $self, $username ) = @_;

    croak "username must be defined"
      unless defined $username;

    croak 'Either noauth or binddn/bindpw need to be specified'
      unless ($self->noauth || ($self->binddn && $self->bindpw));

    my @params;
    @params = ($self->binddn, password=> $self->bindpw)
      unless $self->noauth;

    my $ldap = $self->ldap or return;

    my $mesg = $ldap->bind(@params);

    if ( $mesg->is_error ) {
        croak "LDAP bind error: " . $mesg->error;
    }

    $mesg = $ldap->search(
        base   => $self->basedn,
        sizelimit => 1,
        filter => '(&'
          . $self->user_filter
          . '(' . $self->username_attribute . '=' . $username . '))',
    );

    if ( $mesg->is_error ) {
        croak "LDAP search error: " . $mesg->error;
    }

    my $user;
    if ( $mesg->count > 0 ) {
        my $entry = $mesg->entry(0);
        $self->plugin->app->log(
            debug => "User $username found with DN: ",
            $entry->dn
        );

        my $dbu = $self->_check_user_in_database($username, $entry);

	my $roles = [ map { $_->role->role } $dbu->user_roles];
        my $role_id = {};
        $role_id->{$_} = 1 for @{$roles};

        $user = {
          id       => $dbu->id,
          username => $dbu->username,
          name     => $dbu->name,
          deleted  => 0,
          roles    => $roles,
          role_id  => $role_id,
          name     => $entry->get_value( $self->name_attribute ),
          dn       => $entry->dn,
          map { $_ => scalar $entry->get_value($_) } $entry->attributes,
        };
    }
    else {
        $self->plugin->app->log(
            debug => "User not found via LDAP: $username" );
    }

    $ldap->unbind;
    $ldap->disconnect;

    return $user;
}

=head2 get_user_roles

=cut

sub get_user_roles {
    my ( $self, $username ) = @_;

    croak "username must be defined"
      unless defined $username;

    my $user = $self->get_user_details($username) or return;

    return $user->{roles};
}

sub _check_user_in_database {
  my ($self, $username, $entry) = @_;

  croak "username must be defined"
    unless defined $username;

  my $db_user = $self->schema->resultset('User')->find({username => $username});
  if ($db_user) {
    $db_user->update({lastlogin=>DateTime->now()});
    return $db_user;
  }
  return $self->_create_user_in_db($username, $entry);
}

sub _create_user_in_db {
  my ($self, $username, $entry) = @_;

  croak "username must be defined"
    unless defined $username;

  my $ldap = $self->ldap or return;

  $self->plugin->app->log(
    debug => "Could not find $username in database. Creating new database entry");

  # now get the roles
  my $rsa = $entry->get_value( $self->role_search_attribute) || $entry->dn;
  $self->plugin->app->log(
    debug => "Value for role_search_attribute '".$self->role_search_attribute."': ".($rsa || q{}));

  return unless $rsa;
  my $filter = '(&'
	. $self->role_filter . '('
	. $self->role_member_attribute . '='
	. $rsa . '))';

  $self->plugin->app->log(
    debug => "Searching for roles with the following filter: $filter");

  my $mesg = $ldap->search(
      base   => $self->basedn,
      filter => $filter,
  );

  if ( $mesg->is_error ) {
      $self->plugin->app->log(
	  warning => "LDAP search error: " . $mesg->error );
  }

  my @entries = $mesg->entries;
  my @ldap_roles =
    map { $_->get_value( $self->role_attribute ) } @entries;

  $self->plugin->app->log(
    debug => "Found the following roles in ldap: '@ldap_roles'");

  my $c   = $self->plugin->app->config();
  my @roles = split(',', $c->{initial_roles}->{default} || '');
  my $irm   = $c->{initial_roles}->{mapping};
  for my $r (@ldap_roles) {
    push @roles, $irm->{$r} if $irm->{$r};
  }

  $self->plugin->app->log(debug => "Found the following roles: '@roles'");

  my @roles2create;
  @roles2create = map {{role_id => $_->id}} $self->schema->resultset('Role')->search([map {{role=>$_}} @roles]) if @roles;

  my $ud = {
      username         => $username,
      name             => $entry->get_value( $self->name_attribute ),
      lastlogin       =>  DateTime->now(),
      pw_changed       => 0,
      password         => '',
      deleted          => 1,
      user_roles       => \@roles2create,
  };

  $ldap->unbind;
  $ldap->disconnect;

  return $self->schema->resultset('User')->create($ud);

}

1;
