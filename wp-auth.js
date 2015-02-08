var crypto = require( 'crypto' ),
	phpjs = require( './serialize' );

function sanitizeValue( value ) {
	switch ( typeof value ) {
		case 'boolean':
		case 'object':
			return phpjs.serialize( value ).replace( /(\'|\\)/g, '\\$1' );
		case 'number':
			return Number.toString.call( value );
		case 'string':
			try {
				// If it's a serialized string, serialize it again so it comes back out of the database the same way.
				return phpjs.serialize( phpjs.serialize( phpjs.unserialize( value ) ) ).replace( /(\'|\\)/g, '\\$1' );
			} catch ( ex ) {
				return value.replace( /(\'|\\)/g, '\\$1' );
			}
		default:
			throw new Error( 'Invalid data type: ' + typeof value );
	}
}

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
	this.known_hashes_timeout = {};
	this.meta_cache = {};
	this.meta_cache_timeout = {};

	// Default cache time: 5 minutes
	this.timeout = 300000;
}

WP_Auth.prototype.checkAuth = function( req ) {
	var self = this, data = null;
	if ( req.headers.cookie )
		req.headers.cookie.split( ';' ).forEach( function( cookie ) {
			if ( cookie.split( '=' )[0].trim() == self.cookiename )
				data = cookie.split( '=' )[1].trim().split( '%7C' );
		} );
	else
		return new Invalid_Auth("no cookie");

	if ( !data )
		return new Invalid_Auth("no data in cookie");

	if ( parseInt( data[1] ) < new Date / 1000 )
		return new Invalid_Auth("expired cookie");

	return new Valid_Auth( data, this );
};

WP_Auth.prototype.getUserMeta = function( id, key, callback ) {
	if ( !( id in this.meta_cache_timeout ) )
		this.meta_cache_timeout[id] = {};

	if ( key in this.meta_cache_timeout[id] && this.meta_cache_timeout[id][key] < +new Date ) {
		delete this.meta_cache[id][key];
		delete this.meta_cache_timeout[id][key];
	}

	if ( id in this.meta_cache && key in this.meta_cache[id] ) {
		callback( this.meta_cache[id][key] );
		return;
	}

	var self = this;
	this.db.query( 'select meta_value from ' + this.table_prefix + 'usermeta where meta_key = \'' + sanitizeValue( key ) + '\' and user_id = ' + parseInt( id ) ).on( 'row', function( data ) {
		if ( !( id in self.meta_cache ) )
			self.meta_cache[id] = {};
		try {
			self.meta_cache[id][key] = phpjs.unserialize( data.meta_value );
		} catch( ex ) {
			self.meta_cache[id][key] = data.meta_value;
		}
	} ).on( 'end', function() {
		if ( !( id in self.meta_cache ) )
			self.meta_cache[id] = {};
		if ( !( key in self.meta_cache[id] ) )
			self.meta_cache[id][key] = null;
		self.meta_cache_timeout[id][key] = +new Date + self.timeout;
		callback( self.meta_cache[id][key] );
	} );
};

WP_Auth.prototype.setUserMeta = function( id, key, value ) {
	if ( !( id in this.meta_cache_timeout ) )
		this.meta_cache_timeout[id] = {};

	this.meta_cache[id][key] = value;
	this.meta_cache_timeout[id][key] = +new Date + this.timeout;

	var sanitized_value = sanitizeValue( value );

	var self = this;
	this.db.query( 'delete from' + this.table_prefix + 'usermeta where meta_key = \'' + sanitizeValue( key ) + '\' and user_id = ' + parseInt( id ) );
	this.db.query( 'insert into' + this.table_prefix + 'usermeta (meta_key, user_id, meta_value) VALUES(\'' + sanitizeValue( key ) + '\', ' + parseInt( id ) + ', \'' + sanitized_value + '\')' );
};

WP_Auth.prototype.reverseUserMeta = function( key, value, callback ) {
	for ( var id in this.meta_cache ) {
		if ( key in this.meta_cache[id] && this.meta_cache[id][key] == value ) {
			callback( id );
			return;
		}
	}

	var id = null;

	var self = this;
	this.db.query( 'select user_id from ' + this.table_prefix + 'usermeta where meta_key = \'' + sanitizeValue( key ) + '\' and meta_value = \'' + sanitizeValue( key ) + '\'' ).on( 'row', function( data ) {
		id = data.user_id;
		if ( !( id in self.meta_cache ) )
			self.meta_cache[id] = {};
		if ( !( id in self.meta_cache_timeout ) )
			self.meta_cache_timeout[id] = {};
		self.meta_cache[id][key] = value;
		self.meta_cache_timeout[id][key] = +new Date + this.timeout;
	} ).on( 'end', function() {
		callback( id );
	} );
};

WP_Auth.prototype.getContributors = function( callback ) {
	var self = this;
    var users = [];
	// this.db.query( 'select ID as user_id, user_login from ' + this.table_prefix + 'user' ).on( 'row', function( data ) {});
	this.db.query( 'select user_id, user_login from ' + this.table_prefix + 'usermeta as meta left join ' + this.table_prefix + 'users as user on user.ID = meta.user_id where meta_key = \'wp_user_level\' and meta_value = \'1\'' ).on( 'row', function( data ) {
        users.push( data );
    }).on( 'end', function() {
        callback( users );
    });
};

exports.create = function( wpurl, logged_in_key, logged_in_salt,
				mysql_host, mysql_user, mysql_pass, mysql_db,
				wp_table_prefix ) {
	return new WP_Auth( wpurl, logged_in_key, logged_in_salt,
				mysql_host, mysql_user, mysql_pass, mysql_db,
				wp_table_prefix );
};

function Invalid_Auth(err) { this.err = err; }
Invalid_Auth.prototype.on = function( key, callback ) {
	if ( key != 'auth' )
		return this;
	var self = this;
	process.nextTick( function() {
		callback.call( self, false, 0, self.err );
	} );
	return this;
};

function Valid_Auth( data, auth ) {
	var self = this, user_login = data[0], expiration = data[1], token = data[2], hash = data[3];

	if ( user_login in auth.known_hashes_timeout && auth.known_hashes_timeout[user_login] < +new Date ) {
		delete auth.known_hashes[user_login];
		delete auth.known_hashes_timeout[user_login];
	}

	function parse( pass_frag, id ) {
		var hmac1 = crypto.createHmac( 'md5', auth.salt );
        var key = user_login + '|' + pass_frag + '|' + expiration + '|' + token;
        hmac1.update(key);
        var hkey = hmac1.digest('hex');
        var hmac2 = crypto.createHmac('sha256', hkey);
        hmac2.update(user_login + '|' + expiration + '|' + token);
        var cookieHash = hmac2.digest('hex');
		if ( hash == cookieHash ) {
			self.emit( 'auth', true, id );
		} else {
			self.emit( 'auth', false, 0, "invalid hash" );
		}
	}

	if ( user_login in auth.known_hashes ) {
		return process.nextTick(function() {
			parse( auth.known_hashes[user_login].frag, auth.known_hashes[user_login].id );
		} );
    }


	var found = false;
	auth.db.query( 'select ID, user_pass from ' + auth.table_prefix + 'users where user_login = \'' + user_login.replace( /(\'|\\)/g, '\\$1' ) + '\'' ).on( 'row', function( data ) {
		found = true;
		auth.known_hashes[user_login] = {frag: data.user_pass.substr( 8, 4 ), id: data.ID};
		auth.known_hashes_timeout[user_login] = +new Date + auth.timeout;
	} ).on( 'end', function() {
		if ( !found ) {
			auth.known_hashes[user_login] = {frag: '__fail__', id: 0};
			auth.known_hashes_timeout[user_login] = +new Date + auth.timeout;
		}
		parse( auth.known_hashes[user_login].frag, auth.known_hashes[user_login].id );
	} );
}

require( 'util' ).inherits( Valid_Auth, require( 'events' ).EventEmitter );
