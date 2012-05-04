# Module of Foswiki Collaboration Platform, http://Foswiki.org/
#
# Copyright (C) 2006-9 Sven Dowideit, SvenDowideit@fosiki.com
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 3
# of the License, or (at your option) any later version. For
# more details read LICENSE in the root of this distribution.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
#
# As per the GPL, removal of this notice is prohibited.

=pod

---+ package Foswiki::LoginManager::DrupalLogin

Thie DrupalLogin class uses the Drupal session cookie to auto-login into Foswiki

=cut

package Foswiki::LoginManager::DrupalLogin;

use strict;
use Assert;
use Foswiki::LoginManager::TemplateLogin;
use Foswiki::Contrib::DbiContrib;
use Digest::MD5;
use CGI::Cookie;

@Foswiki::LoginManager::DrupalLogin::ISA =
  ('Foswiki::LoginManager::TemplateLogin');

sub new {
    my ( $class, $session ) = @_;

    my $this = bless( $class->SUPER::new($session), $class );
    $session->enterContext('can_login');

    $this->{DB} = new Foswiki::Contrib::DbiContrib(
        {
            dsn          => $Foswiki::cfg{Plugins}{DrupalUser}{DBI_dsn},
            dsn_user     => $Foswiki::cfg{Plugins}{DrupalUser}{DBI_username},
            dsn_password => $Foswiki::cfg{Plugins}{DrupalUser}{DBI_password}
        }
    );

    return $this;
}

sub finish {
    my $this = shift;

#need to be careful when using cached_connections to only call disconnect once :/
#$this->{DB}->disconnect();
    undef $this->{DB};

    $this->SUPER::finish();
    return;
}

=pod

---++ ObjectMethod loadSession()

add Drupal cookie to the session management

=cut

sub loadSession {
    my $this    = shift;
    my $foswiki = $this->{session};
    my $query   = $foswiki->{request};

    ASSERT( $this->isa('Foswiki::LoginManager::DrupalLogin') ) if DEBUG;

    my $cookie_domain = $foswiki->{request}->header('Host');
    $cookie_domain = $Foswiki::cfg{Plugins}{DrupalUser}{DrupalHostname}
      if ( $Foswiki::cfg{Plugins}{DrupalUser}{DrupalHostname} );
    return $this->SUPER::loadSession() unless ($cookie_domain);

    $cookie_domain =~ s/^(\.|www\.)//; #remove leading dot (wtf) or leading www.

    my $DrupalCookieName = 'SESS' . Digest::MD5::md5_hex($cookie_domain);
    my %cookies          = fetch CGI::Cookie;

    if ( $query->param('logout') && defined( $cookies{$DrupalCookieName} ) ) {
        undef $cookies{$DrupalCookieName};
        my $cookie = CGI::Cookie->new(
            -name    => $DrupalCookieName,
            -value   => undef,
            -path    => '/',
            -expires => 0,
        );
        $this->addCookie($cookie);
        $this->_trace("logout Drupal session cookie too");
    }

# LoginManager::loadSession does a redirect on logout, so we have to deal with logout before it.
    my $authUser = $this->SUPER::loadSession();

    #check drupal session.
    if ( !defined($authUser) and defined( $cookies{$DrupalCookieName} ) ) {
        my $id          = $cookies{$DrupalCookieName}->value;
        my $userDataset = $this->{DB}->select(
'SELECT name FROM sessions s JOIN users u ON u.uid=s.uid WHERE sid = ?',
            $id
        );
        if ( exists $$userDataset[0] ) {
            $authUser = $$userDataset[0]{name};
            $this->_trace(
"used Drupal Session cookie and database lookup to find $authUser"
            );
        }
        $this->userLoggedIn($authUser);
    }
    else {
        if ( $Foswiki::cfg{Plugins}{DrupalUser}{DrupalAuthOnly} ) {

            #no Drupal session - goto guest.
            $authUser = $Foswiki::cfg{DefaultUserLogin};
            $this->userLoggedIn($authUser);
        }
    }

    return $authUser;
}

=begin TML

---++ ObjectMethod loginUrl () -> $loginUrl

over-ride the login url

=cut

sub loginUrl {
    my $this = shift;

    if ( $Foswiki::cfg{Plugins}{DrupalUser}{DrupalAuthOnly} ) {
        return $Foswiki::cfg{Plugins}{DrupalUser}{DrupalAuthURL};
    }
    else {
        return $this->SUPER::loginUrl();
    }
}

1;
