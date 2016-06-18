package Dancer2::Plugin::Auth::Extensible::Provider::Config;

use Dancer2::Core::Types qw/ArrayRef/;

use Moo;
with "Dancer2::Plugin::Auth::Extensible::Role::Provider";
use namespace::clean;

our $VERSION = '0.600';

{
    package User;
    use Dancer2::Core::Types qw/Str/;
    use Moo;
    with "Dancer2::Plugin::Auth::Extensible::Role::User";
    use namespace::clean;

    # We need the underlying hash to have user/pass for backward-compatibility
    # with code that expects these two rather than username/password of
    # a normal User object. At some point we'll add deprecation via
    # a warning in BUILD.

    has user => (
        is       => 'ro',
        isa      => Str,
        required => 1,
    );

    has '+username' => (
        lazy => 1,
        default => sub { $_[0]->user },
    );

    has pass => (
        is       => 'ro',
        isa      => Str,
        required => 1,
    );

    has '+password' => (
        lazy => 1,
        default => sub { $_[0]->pass },
    );
}

=head1 NAME 

Dancer2::Plugin::Auth::Extensible::Provider::Config - example auth provider using app config


=head1 DESCRIPTION

This is a simple authentication provider which authenticates based on a list of
usernames, passwords (crypted, preferably - see below) and role specifications
provided in the realm definition in your app's config file.

This class is primarily intended as an example of what an authentication 
provider class should do; however, if you just want simple user authentication
with user details stored in your app's config file, it may well suit your needs.

See L<Dancer2::Plugin::Auth::Extensible> for details on how to use the
authentication framework.

=head1 SYNOPSIS

In your app's C<config.yml>:

    plugins:
        Auth::Extensible:
            realms:
                config:
                    provider: Config
                    users:
                        - user: dave
                          pass: supersecret
                          roles:
                            - Developer
                            - Manager
                            - BeerDrinker
                        - user: bob
                          pass: '{SSHA}+2u1HpOU7ak6iBR6JlpICpAUvSpA/zBM'
                          roles:
                            - Tester

As you can see, you can define the usernames, passwords (please use crypted
passwords, RFC2307-style, not plain text (although plain text *is* supported,
but really not a good idea), and the roles for each user (if you're
not planning to use roles, omit the roles section from each user entirely).

=head1 ATTRIBUTES

=head2 users

Array reference containing users from configuration.

=cut

has users => (
    is       => 'ro',
    isa      => ArrayRef,
    required => 1,
    coerce   => sub {
        [ map { User->new($_) } @{ $_[0] } ];
    },
);

=head1 METHODS

=head2 authenticate_user $username, $password

=cut

sub authenticate_user {
    my ($self, $username, $password) = @_;
    my $user = $self->get_user_details($username) or return;
    return $user->check_password($password);
}

=head2 get_user_details $username

=cut

# Just return the whole user definition from the config; this way any additional
# fields defined for users will just get passed through.
sub get_user_details {
    my ($self, $username) = @_;
    my ($user) = grep {
        $_->username eq $username 
    } @{ $self->users };
    return $user;
}

=head2 get_user_roles $username

=cut

sub get_user_roles {
    my ($self, $username) = @_;

    my $user = $self->get_user_details($username) or return;
    return $user->roles;
}

1;
