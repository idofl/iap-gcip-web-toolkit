/*
 * Copyright 2020 Google Inc. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the
 * License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 * express or implied. See the License for the specific language governing permissions and
 * limitations under the License.
 */

import {HttpServerRequestHandler} from '../../server/utils/http-server-request-handler';
import requestPromise = require('request-promise');

/** Interface defining a Google OAuth access token. */
export interface GoogleOAuthAccessToken {
  access_token: string;
  expires_in: number;
}

/** Interface defining an OAuth access token manager used to retrieve tokens. */
export interface AccessTokenManager {
  getAccessToken(): Promise<string>;
}

/** Interface defining a credential object used to retrieve access tokens. */
export interface Credential {
  getAccessToken(): Promise<GoogleOAuthAccessToken>;
}

export interface GcipToken {
  verifyAccessToken(): Promise<boolean>;
  getNameIdentifier(token: any): string;
}

/** Metadata server access token endpoint. */
const METADATA_SERVER_ACCESS_TOKEN_URL =
    'http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token';

const REFRESH_TOKEN_URL =
    'https://securetoken.googleapis.com/v1/token?key=';

const CLIENT_CERT_URL = 
    'https://www.googleapis.com/robot/v1/metadata/x509/securetoken@system.gserviceaccount.com';

/** The default OAuth scope to include in the access token. */
const DEFAULT_OAUTH_SCOPE = 'https://www.googleapis.com/auth/cloud-platform';
/** Time offset in milliseconds for forcing a refresh before a token expires. */
export const OFFSET = 30000;
/** Network request timeout duration. */
const TIMEOUT_DURATION = 10000;
/** Default error message to show when access token fails to be obtained. */
const DEFAULT_ERROR_MESSAGE = 'Unable to retrieve an OAuth access tokens.';

/** Utility used to manage OAuth access tokens generated via the metadata server. */
export class TokenManager implements Credential {
  private readonly metadataServerTokenRetriever: HttpServerRequestHandler;
  private expirationTime: number;
  private accessToken: string | null;

  /**
   * Instantiates an instance of a token manager used to retrieve OAuth access
   * tokens retrieved from the metadata server.
   * @param scopes The OAuth scopes to set on the generated access tokens.
   */
  constructor(scopes: string[] = [DEFAULT_OAUTH_SCOPE]) {
    this.metadataServerTokenRetriever = new HttpServerRequestHandler({
      method: 'GET',
      url: `${METADATA_SERVER_ACCESS_TOKEN_URL}?scopes=${scopes.join(',')}`,
      headers: {
        'Metadata-Flavor': 'Google',
      },
      timeout: TIMEOUT_DURATION,
    });
  }

  /**
   * @return A promise that resolves with a Google OAuth access token.
   *     A cached token is returned if it is not yet expired.
   */
  getAccessToken(forceRefresh: boolean = false): Promise<GoogleOAuthAccessToken> {
    const currentTime = new Date().getTime();
    if (!forceRefresh &&
        (this.accessToken &&
         currentTime + OFFSET <= this.expirationTime)) {
      return Promise.resolve({
        access_token: this.accessToken,
        expires_in: (this.expirationTime - currentTime) / 1000,
      });
    }
    return this.metadataServerTokenRetriever.send(null, DEFAULT_ERROR_MESSAGE)
      .then((httpResponse) => {
        if (httpResponse.statusCode === 200 && httpResponse.body) {
          const tokenResponse: GoogleOAuthAccessToken = typeof httpResponse.body === 'object' ?
              httpResponse.body : JSON.parse(httpResponse.body);
          this.accessToken = tokenResponse.access_token;
          this.expirationTime = currentTime + (tokenResponse.expires_in * 1000);
          return tokenResponse;
        } else {
          throw new Error(DEFAULT_ERROR_MESSAGE);
        }
      });
  }

  /** Reset cached access tokens. */
  reset() {
    this.accessToken = null;
  }
}

export class GcipTokenManager implements GcipToken {
  private readonly googleSigningCertRetriever: HttpServerRequestHandler;
  private expirationTime: number;
  private clientCerts: any;
  private accessToken: string | null;
  private refreshToken: string | null;
  private apiKey: string;

  /**
   */
  constructor(accessToken:string, refreshToken: string, apiKey: string) {
    this.googleSigningCertRetriever = new HttpServerRequestHandler({
      method: 'GET',
      url: CLIENT_CERT_URL,
      timeout: TIMEOUT_DURATION,
    });
   
    this.accessToken = accessToken;
    this.refreshToken = refreshToken;
    this.apiKey = apiKey;
  }

  private async RefreshToken() {

  }

  getNameIdentifier(token: any): string {
    return token.email || token.firebase.identities[token.firebase.sign_in_provider][0];
  }

  async verifyAccessToken(allowRefresh:boolean=true): Promise<any> {
    if (!this.clientCerts) {
      const httpResponse = await this.googleSigningCertRetriever.send(null, "Unable to retrieve Google's signing certificate");
      
      if (httpResponse.statusCode === 200 && httpResponse.body) {
          this.clientCerts = httpResponse.body;
      } else {
          throw new Error("Unable to retrieve Google's signing certificate");
      }
    }

    var jwt = require('jsonwebtoken');
    const decodedToken = jwt.decode(this.accessToken, {complete: true});
    const kid = decodedToken.header.kid;
    if (this.clientCerts[kid]) {
      try {
        const decoded = jwt.verify(this.accessToken, this.clientCerts[kid]);
        return decoded;
      } catch(err) {
          if (err.name == 'TokenExpiredError' && allowRefresh) {
            // Refresh the token and retry
            const options = { 
              method: 'POST',
              uri: REFRESH_TOKEN_URL+this.apiKey,
              form: {
                grant_type: 'refresh_token',
                refresh_token: this.refreshToken,
              },
            }

            try {
              const result = await requestPromise(options);
              this.accessToken = JSON.parse(result).access_token;
            } catch (err) {
              throw new Error(`Failed refreshing access token: ${err.message}`);
            }

            // Retry validation with a new access token (no refresh this time!)
            return await this.verifyAccessToken(false);
          }
          throw new Error(`Failed verifying JWT of user: ${err.message}`);
      }
    }
    else {
      throw new Error("JWT signing cert not found");
    }
  }
}
