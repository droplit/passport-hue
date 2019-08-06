
/**
 * Module dependencies.
 */
var util = require('util'),
    OAuth2Strategy = require('passport-oauth2').Strategy,
    request = require('request'),
    crypto = require('crypto');

/**
 * `Strategy` constructor.
 *
 * The Hue authentication strategy authenticates with the Hue OAuth server to
 * get an access_token and refresh token for the Hue API
 *
 * Options:
 *   - `clientID`       Hue client ID
 *   - `clientSecret`   Hue client secret
 *   - `appID`          Hue app ID
 *   - `deviceID`       Hue client ID
 *   - `deviceName`  
 *
 * Examples:
 *     const HueStrategy = require('passport-hue').Strategy;    
 *  
 *     passport.use(new HueStrategy({
 *       clientID: CLIENT_ID,
 *       clientSecret: CLIENT_SECRET,
 *       appID: APP_ID,
 *       deviceID: DEVICE_ID,
 *       deviceName?: DEVICE_NAME,
 *     }));
 *
 * @param {Object} options
 * @param {Funciton} verify (optional)
 * @api public
 */
function HueStrategy(options, verify) {
    options = options || {};
    const { clientID, appID, deviceID, deviceName, clientSecret } = options;
    if (!clientID) throw new Error('clientID requried in Hue strategy');
    if (!clientSecret) throw new Error('clientSecret requried in Hue strategy');
    if (!appID) throw new Error('appID requried in Hue strategy');
    if (!deviceID) throw new Error('deviceID requried in Hue strategy');
    options.authorizationURL = `https://api.meethue.com/oauth2/auth?clientid=${clientID}&appid=${appID}&deviceid=${deviceID}&devicename=${deviceName}&response_type=code`;
    options.tokenURL = 'https://api.meethue.com/oauth2/token?grant_type=authorization_code';
    options.state = true;
    verify = verify || function verify(accessToken, refreshToken, params, profile, done) {
        done(null, { accessToken, refreshToken, expires_in: params.expires_in });
    }
    OAuth2Strategy.call(this, options, verify);
    this.name = 'hue';
    this._oauth2.getOAuthAccessToken = function (code, params, done) {
        const { clientID, clientSecret } = options;
        request({
            method: 'POST',
            url: `https://api.meethue.com/oauth2/token?grant_type=authorization_code&code=${code}`,
        }, function (err, res, body) {
            if (err) {
                return done(err);
            }
            if (res.statusCode !== 401) {
                return done(new Error('Invalid code or state'))
            }
            if (!res.headers['www-authenticate']) {
                return done(new Error('Unexpected error: www-authenticate headers not included in response'))
            }
            const [digestRealmStr, nonceStr] = res.headers['www-authenticate'].replace(/\"/g, '').split(',');
            const [_, digestRealm] = digestRealmStr.split('=');
            const [__, nonce] = nonceStr.split('=');

            const hash1 = md5(`${clientID}:${digestRealm}:${clientSecret}`);
            const hash2 = md5('POST:/oauth2/token')
            const response = md5(`${hash1}:${nonce}:${hash2}`);
            const authStr = `Digest username="${clientID}", realm="${digestRealm}", nonce="${nonce}", uri="/oauth2/token", response="${response}"`;
            // return nonce
            request({
                method: 'POST',
                url: `https://api.meethue.com/oauth2/token?grant_type=authorization_code&code=${code}`,
                headers: {
                    Authorization: authStr
                }
            }, function (err, res, body) {
                if (err) {
                    return done(err);
                }
                if (res.statusCode !== 200) {
                    return done(new Error('Unable to retrieve access token. One of the following are invalid: code, state, clientID, clientSecret '))
                }
                const {
                    access_token,
                    access_token_expires_in,
                    refresh_token
                } = JSON.parse(body);
                const params = { expires_in: access_token_expires_in };
                done(null, access_token, refresh_token, params);
            });
        });

        function md5(str) {
            return hash(str, 'md5', 'hex');
        }

        function hash(str, algorithm, outEncoding) {
            const hash = crypto.createHash(algorithm);
            hash.update(str);
            return hash.digest(outEncoding || 'base64');
        }
    };
}

/**
 * Inherit from `OAuth2Strategy`.
 */
util.inherits(HueStrategy, OAuth2Strategy);

HueStrategy.prototype.authenticate = function (req, options) {
    console.log('Strategy.prototype.authenticate', options);
    if (req.query && req.query.error) {
        console.log('Strategy.prototype.authenticate: error');
        return this.fail(req.query.error);
    }
    console.log('Strategy.prototype.authenticate: calling base auth, no error');
    OAuth2Strategy.prototype.authenticate.call(this, req, options);
};

/**
 * Expose `Strategy` directly from package.
 */
exports = module.exports = HueStrategy;

/**
 * Export constructors.
 */
exports.Strategy = HueStrategy;