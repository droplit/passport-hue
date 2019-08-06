import { Strategy as OAuth2Strategy } from 'passport-oauth2';
export type HueStrategyOptions = {
    clientID: string,
    clientSecret: string
    appID: string,
    deviceID: string,
    deviceName?: string
}
// declare class HueStrategy extends Strategy {};
export function Strategy(options: HueStrategyOptions): OAuth2Strategy;