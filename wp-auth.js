/* TO USE:
  npm install mysql-native

  var wp_auth = require('wp-auth').create( 'http://my-blog.example',
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
*/

var crypto = require( 'crypto' );

function WP_Auth( wpurl, logged_in_key, logged_in_salt,
				mysql_host, mysql_user, mysql_pass, mysql_db,
				wp_table_prefix ) {
	var md5 = crypto.createHash( 'md5' );
	md5.update( wpurl );
	this.cookiename = 'wordpress_logged_in_' + md5.digest( 'hex' );
	this.salt = logged_in_key + logged_in_salt;

	this.db = require( 'mysql-native' ).createTCPClient( mysql_host );
	this.db.auth( mysql_db, mysql_user, mysql_pass );
	this.table_prefix = wp_table_prefix;

	this.known_hashes = {};
	this.meta_cache = {};
}

WP_Auth.prototype.checkAuth = function( req ) {
	var self = this, data = null;
	if( req.headers.cookie )
		req.headers.cookie.split( ';' ).forEach( function( cookie ) {
			if ( cookie.split( '=' )[0].trim() == self.cookiename )
				data = cookie.split( '=' )[1].trim().split( '%7C' );
		} );
	else
		return new Invalid_Auth();

	if ( !data )
		return new Invalid_Auth();

	if ( parseInt( data[1] ) < new Date / 1000 )
		return new Invalid_Auth();

	return new Valid_Auth( data, this );
};

WP_Auth.prototype.getUserMeta = function( id, key, callback ) {
	if ( id in this.meta_cache && key in this.meta_cache[id] ) {
		callback( this.meta_cache[id][key] );
		return;
	}

	var self = this;
	this.db.query( 'select meta_value from ' + this.table_prefix + 'usermeta where meta_key = \'' + key.replace( /(\'|\\)/g, '\\$1' ) + '\' and user_id = ' + parseInt( id ) ).on( 'row', function( data ) {
		if ( !( id in self.meta_cache ) )
			self.meta_cache[id] = {};
		self.meta_cache[id][key] = data.meta_value;
	} ).on( 'end', function() {
		if ( !( id in self.meta_cache ) )
			self.meta_cache[id] = {};
		if ( !( key in self.meta_cache[id] ) )
			self.meta_cache[id][key] = null;
		callback( self.meta_cache[id][key] );
	} );
};

exports.create = function( wpurl, logged_in_key, logged_in_salt,
				mysql_host, mysql_user, mysql_pass, mysql_db,
				wp_table_prefix ) {
	return new WP_Auth( wpurl, logged_in_key, logged_in_salt,
				mysql_host, mysql_user, mysql_pass, mysql_db,
				wp_table_prefix );
};

function Invalid_Auth() {}
Invalid_Auth.prototype.on = function( key, callback ) {
	if ( key != 'auth' )
		return this;
	var self = this;
	process.nextTick( function() {
		callback.call( self, false, 0 );
	} );
	return this;
};

function Valid_Auth( data, auth ) {
	var self = this, user_login = data[0], expiration = data[1], hash = data[2];

	function parse( pass_frag, id ) {
		var hmac1 = crypto.createHmac( 'md5', auth.salt );
		hmac1.update( user_login + pass_frag + '|' + expiration );
		var hmac2 = crypto.createHmac( 'md5', hmac1.digest( 'hex' ) );
		hmac2.update( user_login + '|' + expiration );
		if ( hash == hmac2.digest( 'hex' ) ) {
			self.emit( 'auth', true, id );
		} else {
			self.emit( 'auth', false, 0 );
		}
	}

	if ( user_login in auth.known_hashes )
		process.nextTick(function() {
			parse( auth.known_hashes[user_login].frag, auth.known_hashes[user_login].id );
		} );

	var found = false;
	auth.db.query( 'select ID, user_pass from ' + auth.table_prefix + 'users where user_login = \'' + user_login.replace( /(\'|\\)/g, '\\$1' ) + '\'' ).on( 'row', function( data ) {
		found = true;
		auth.known_hashes[user_login] = {frag: data.user_pass.substr( 8, 4 ), id: data.ID};
	} ).on( 'end', function() {
		if ( !found ) {
			auth.known_hashes[user_login] = {frag: '__fail__', id: 0};
		}
		parse( auth.known_hashes[user_login].frag, auth.known_hashes[user_login].id );
	} );
}

require( 'util' ).inherits( Valid_Auth, require( 'events' ).EventEmitter );
