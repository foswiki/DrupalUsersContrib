# ---+ User Managers
# ---++ Drupal User Manager
# to use DrupalUsersMapping, you need to set the following settings in the "Security setup" above
# <ol><li>
# UserMappingManager = 'Foswiki::Users::DrupalUserMapping'
# </li><li>
# (optional) LoginManager = 'Foswiki::LoginManager::DrupalLogin' (This setting will allow Foswiki to use the 'stay logged in' cookie that Drupal provides.)
# </li></ol>

# **STRING 50**
# The DSN to connect to the Drupal Database.
$Foswiki::cfg{Plugins}{DrupalUser}{DBI_dsn} = 'dbi:mysql:drupal:localhost';

# **STRING 25**
# The user to connect to the phpBB3 Database.
$Foswiki::cfg{Plugins}{DrupalUser}{DBI_username} = 'mysql_user';

# **PASSWORD**
# The password to connect to the phpBB3 Database.
$Foswiki::cfg{Plugins}{DrupalUser}{DBI_password} = 'mysql_password';

# **STRING 25**
# The hostname that both your Drupal site and your Foswiki Site are at.
# this is used to identify the Drupal session cookie, and so assumes there is 
# only _one_ hostname used to access your site. (leave blank to use hostname from URL request.
$Foswiki::cfg{Plugins}{DrupalUser}{DrupalHostname} = '';

# **BOOLEAN**
# Over-ride Foswiki authentication using _only_ the Drupal sessions
# If there is no Drupal Session cookie, Foswiki will use the Guest user.
# NOTE: you will need to specify a Drupal Login UI URL for Foswiki to redirect to to authenticate
$Foswiki::cfg{Plugins}{DrupalUser}{DrupalAuthOnly} = $FALSE;

# **STRING 25**
# Drupal Login UI URL for Foswiki to redirect to to authenticate - used if =DrupalAuthOnly= is set to true
$Foswiki::cfg{Plugins}{DrupalUser}{DrupalAuthURL} = '';