# Passport Hue Strategy

Strategy to authenticate with Hue via OAuth2 in Passport

For more details, read the Ecobee developer docs at https://developers.meethue.com/develop/hue-api/remote-authentication/

## Installation

`$ npm install passport-hue`

## Usage

Assuming an [express](http://expressjs.com/) app:

```
const HueStrategy = require('passport-hue').Strategy;

passport.use(new HueStrategy({
    clientID: CLIENT_ID,
    clientSecret: CLIENT_SECRET,
    appID: APP_ID,
    deviceID: DEVICE_ID,
    deviceName?: DEVICE_NAME,
}));

app.get('/auth/hue', passport.authenticate('hue'));
app.get('/auth/hue/callback',
    passport.authenticate('hue', {}),
    function (req, res) {
        // access token is in req.user.accessToken
        // refresh token is in req.user.refreshToken
        // expires in req.user.expires_in seconds
    }
);
```

## License

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
