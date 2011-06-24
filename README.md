TO INSTALL:
===========
    npm install wordpress-auth

TO USE:
=======
In your init:

    var wp_auth = require('wordpress-auth').create( 'http://my-blog.example',
                          'LOGGED_IN_KEY from wp-config.php',
                          'LOGGED_IN_SALT from wp-config.php',
                          'MySQL host',
                          'MySQL username',
                          'MySQL password',
                          'MySQL database',
                          'WordPress table prefix (eg. wp_)' );

When you get a HTTP request and you need to verify auth:

    wp_auth.checkAuth( req ).on( 'auth', function( auth_is_valid, user_id ) {
        auth_is_valid; // true if the user is logged in, false if they are not
        user_id; // the ID number of the user or 0 if the user is not logged in
    } );

To get a usermeta value:

    wp_auth.getUserMeta( user_id, 'meta_key (eg. occupation)', function( data ) {
        // data is null if the user doesn't exist or doesn't have the key.
        // Otherwise, it is the value you would get in WordPress (unserialized intelligently)
    } );

To set a usermeta value:

    wp_auth.setUserMeta( user_id, 'meta_key (eg. occupation)', 'meta_value (eg. Eating spaghetti)' );

To get a user_id from a usermeta value:

    wp_auth.reverseUserMeta( 'meta_key (eg. occupation)', 'meta_value (eg. Eating spaghetti)', function( id ) {
        // id is null if no user could be found with the given meta key value pair
        // Otherwise, it is the ID of the user
        // If multiple users matched, only one will be given
    } );
